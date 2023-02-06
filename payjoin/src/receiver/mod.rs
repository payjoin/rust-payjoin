use std::cmp::max;
use std::convert::TryFrom;

use bitcoin::util::psbt::PartiallySignedTransaction as UncheckedPsbt;
use bitcoin::{AddressType, OutPoint, Script, TxOut};

mod error;
mod optional_parameters;

use error::InternalRequestError;
pub use error::RequestError;
use optional_parameters::Params;
use rand::seq::SliceRandom;

use crate::fee_rate::FeeRate;
use crate::psbt::Psbt;
use crate::weight::Weight;

pub trait Headers {
    fn get_header(&self, key: &str) -> Option<&str>;
}

pub struct UncheckedProposal {
    psbt: Psbt,
    params: Params,
}

pub struct MaybeInputsOwned {
    psbt: Psbt,
    params: Params,
}

pub struct MaybeMixedInputScripts {
    psbt: Psbt,
    params: Params,
}

pub struct MaybeInputsSeen {
    psbt: Psbt,
    params: Params,
}

impl UncheckedProposal {
    pub fn from_request(
        body: impl std::io::Read,
        query: &str,
        headers: impl Headers,
    ) -> Result<Self, RequestError> {
        use crate::bitcoin::consensus::Decodable;

        let content_type = headers
            .get_header("content-type")
            .ok_or(InternalRequestError::MissingHeader("Content-Type"))?;
        if !content_type.starts_with("text/plain") {
            return Err(InternalRequestError::InvalidContentType(content_type.to_owned()).into());
        }
        let content_length = headers
            .get_header("content-length")
            .ok_or(InternalRequestError::MissingHeader("Content-Length"))?
            .parse::<u64>()
            .map_err(InternalRequestError::InvalidContentLength)?;
        // 4M block size limit with base64 encoding overhead => maximum reasonable size of content-length
        if content_length > 4_000_000 * 4 / 3 {
            return Err(InternalRequestError::ContentLengthTooLarge(content_length).into());
        }

        // enforce the limit
        let mut limited = body.take(content_length);
        let mut reader = base64::read::DecoderReader::new(&mut limited, base64::STANDARD);
        let unchecked_psbt =
            UncheckedPsbt::consensus_decode(&mut reader).map_err(InternalRequestError::Decode)?;
        let psbt = Psbt::try_from(unchecked_psbt).map_err(InternalRequestError::Psbt)?;

        let pairs = url::form_urlencoded::parse(query.as_bytes());
        let params = Params::from_query_pairs(pairs).map_err(InternalRequestError::SenderParams)?;

        // TODO check that params are valid for the request's Original PSBT

        Ok(UncheckedProposal { psbt, params })
    }

    /// The Sender's Original PSBT
    pub fn get_transaction_to_schedule_broadcast(&self) -> bitcoin::Transaction {
        self.psbt.clone().extract_tx()
    }

    /// Call after checking that the Original PSBT can be broadcast.
    ///
    /// Receiver MUST check that the Original PSBT from the sender
    /// can be broadcast, i.e. `testmempoolaccept` bitcoind rpc returns { "allowed": true,.. }
    /// for `get_transaction_to_check_broadcast()` before calling this method.
    ///
    /// Do this check if you generate bitcoin uri to receive PayJoin on sender request without manual human approval, like a payment processor.
    /// Such so called "non-interactive" receivers are otherwise vulnerable to probing attacks.
    /// If a sender can make requests at will, they can learn which bitcoin the receiver owns at no cost.
    /// Broadcasting the Original PSBT after some time in the failure case makes incurs sender cost and prevents probing.
    ///
    /// Call this after checking downstream.
    pub fn check_can_broadcast(
        self,
        can_broadcast: impl Fn(&bitcoin::Transaction) -> bool,
    ) -> Result<MaybeInputsOwned, RequestError> {
        if can_broadcast(&self.psbt.clone().extract_tx()) {
            Ok(MaybeInputsOwned { psbt: self.psbt, params: self.params })
        } else {
            Err(RequestError::from(InternalRequestError::OriginalPsbtNotBroadcastable))
        }
    }

    /// Call this method if the only way to initiate a PayJoin with this receiver
    /// requires manual intervention, as in most consumer wallets.
    ///
    /// So-called "non-interactive" receivers, like payment processors, that allow arbitrary requests are otherwise vulnerable to probing attacks.
    /// Those receivers call `get_transaction_to_check_broadcast()` and `attest_tested_and_scheduled_broadcast()` after making those checks downstream.
    pub fn assume_interactive_receiver(self) -> MaybeInputsOwned {
        MaybeInputsOwned { psbt: self.psbt, params: self.params }
    }
}

impl MaybeInputsOwned {
    /// Check that the Original PSBT has no receiver-owned inputs.
    /// Return original-psbt-rejected error or otherwise refuse to sign undesirable inputs.
    ///
    /// An attacker could try to spend receiver's own inputs. This check prevents that.
    pub fn check_inputs_not_owned(
        self,
        is_owned: impl Fn(&Script) -> bool,
    ) -> Result<MaybeMixedInputScripts, RequestError> {
        let owned_script = self
            .psbt
            .input_pairs()
            .filter_map(|input| {
                // `None` txouts should already be removed by the broadcast check, so filter them, don't error.
                input.previous_txout().ok().map(|txout| txout.script_pubkey.to_owned())
            })
            .filter(|script| is_owned(script))
            .next();

        match owned_script {
            Some(owned_script) =>
                Err(RequestError::from(InternalRequestError::InputOwned(owned_script))),
            None => Ok(MaybeMixedInputScripts { psbt: self.psbt, params: self.params }),
        }
    }
}

impl MaybeMixedInputScripts {
    /// Verify the original transaction did not have mixed input types
    /// Call this after checking downstream.
    ///
    /// Note: mixed spends do not necessarily indicate distinct wallet fingerprints.
    /// This check is intended to prevent some types of wallet fingerprinting.
    pub fn check_no_mixed_input_scripts(self) -> Result<MaybeInputsSeen, RequestError> {
        use crate::input_type::InputType;

        let input_scripts = self
            .psbt
            .input_pairs()
            .filter_map(|input| {
                // `None` txouts should already be removed by the broadcast check, so filter them, don't error.
                input
                    .previous_txout()
                    .ok()
                    .map(|txout| InputType::from_spent_input(txout, &input.psbtin))
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| RequestError::from(InternalRequestError::InputType(e)))?;

        let first_input_script = input_scripts
            .first()
            .ok_or(RequestError::from(InternalRequestError::OriginalPsbtNotBroadcastable))?;

        if let Some(mismatch) =
            input_scripts.iter().find(|input_script| input_script != &first_input_script)
        {
            return Err(RequestError::from(InternalRequestError::MixedInputScripts(
                *first_input_script,
                *mismatch,
            )));
        }

        Ok(MaybeInputsSeen { psbt: self.psbt, params: self.params })
    }
}

impl MaybeInputsSeen {
    /// Make sure that the original transaction inputs have never been seen before.
    /// This prevents probing attacks. This prevents reentrant PayJoin, where a sender
    /// proposes a PayJoin PSBT as a new Original PSBT for a new PayJoin.
    pub fn check_no_inputs_seen_before(
        self,
        is_known: impl Fn(&OutPoint) -> bool,
    ) -> Result<OutputsUnknown, RequestError> {
        let psbt: Psbt = Psbt::try_from(self.psbt.clone()).unwrap();
        let mut input_scripts = psbt.input_pairs().map(|input| input.txin.previous_output);

        if let Some(known_input) = input_scripts.find(|op| is_known(op)) {
            return Err(RequestError::from(InternalRequestError::InputSeen(known_input.clone())));
        }
        Ok(OutputsUnknown { psbt: self.psbt, params: self.params })
    }
}

pub struct OutputsUnknown {
    psbt: Psbt,
    params: Params,
}

impl OutputsUnknown {
    /// Find which outputs belong to the receiver
    pub fn identify_receiver_outputs(
        self,
        is_receiver_output: impl Fn(&Script) -> bool,
    ) -> Result<PayjoinProposal, RequestError> {
        let owned_vouts: Vec<usize> = self
            .psbt
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .filter_map(
                |(vout, txo)| {
                    if is_receiver_output(&txo.script_pubkey) {
                        Some(vout)
                    } else {
                        None
                    }
                },
            )
            .collect();

        if owned_vouts.len() < 1 {
            return Err(RequestError::from(InternalRequestError::MissingPayment));
        }

        Ok(PayjoinProposal { psbt: self.psbt, params: self.params, owned_vouts })
    }
}

pub struct PayjoinProposal {
    psbt: Psbt,
    params: Params,
    owned_vouts: Vec<usize>,
}

/// A mutable checked proposal that the receiver may contribute inputs to.
impl PayjoinProposal {
    pub fn utxos_to_be_locked(&self) -> impl '_ + Iterator<Item = &bitcoin::OutPoint> {
        self.psbt.unsigned_tx.input.iter().map(|input| &input.previous_output)
    }

    pub fn is_output_substitution_disabled(&self) -> bool {
        self.params.disable_output_substitution
    }

    pub fn contribute_witness_input(&mut self, txo: TxOut, outpoint: OutPoint) {
        // The payjoin proposal must not introduce mixed input sequence numbers
        let original_sequence =
            self.psbt.unsigned_tx.input.first().map(|input| input.sequence).unwrap_or_default();

        // Add the value of new receiver input to receiver output
        let txo_value = txo.value;
        let vout_to_augment =
            self.owned_vouts.choose(&mut rand::thread_rng()).expect("owned_vouts is empty");
        self.psbt.unsigned_tx.output[*vout_to_augment].value += txo_value;

        self.psbt
            .inputs
            .push(bitcoin::psbt::Input { witness_utxo: Some(txo), ..Default::default() });
        self.psbt.unsigned_tx.input.push(bitcoin::TxIn {
            previous_output: outpoint,
            sequence: original_sequence,
            ..Default::default()
        });
    }

    pub fn contribute_non_witness_input(&mut self, tx: bitcoin::Transaction, outpoint: OutPoint) {
        // The payjoin proposal must not introduce mixed input sequence numbers
        let original_sequence =
            self.psbt.unsigned_tx.input.first().map(|input| input.sequence).unwrap_or_default();

        // Add the value of new receiver input to receiver output
        let txo_value = tx.output[outpoint.vout as usize].value;
        let vout_to_augment =
            self.owned_vouts.choose(&mut rand::thread_rng()).expect("owned_vouts is empty");
        self.psbt.unsigned_tx.output[*vout_to_augment].value += txo_value;

        // Add the new input to the PSBT
        self.psbt
            .inputs
            .push(bitcoin::psbt::Input { non_witness_utxo: Some(tx), ..Default::default() });
        self.psbt.unsigned_tx.input.push(bitcoin::TxIn {
            previous_output: outpoint,
            sequence: original_sequence,
            ..Default::default()
        });
    }

    /// Just replace an output address with
    pub fn substitute_output_address(&mut self, substitute_address: bitcoin::Address) {
        self.psbt.unsigned_tx.output[self.owned_vouts[0]].script_pubkey =
            substitute_address.script_pubkey();
    }

    /// Return a Payjoin Proposal PSBT that the sender will find acceptable.
    ///
    /// When the receiver is satisfied with their contributions, they can apply either their own
    /// [`min_feerate`], specified here, or the sender's optional min_feerate, whichever is greater.
    ///
    /// This attempts to calculate any network fee owed by the receiver, subtract it from their output,
    /// and return a PSBT that can produce a consensus-valid transaction that the sender will accept.
    pub fn extract_psbt(
        mut self,
        min_feerate_sat_per_vb: Option<u64>,
    ) -> Result<UncheckedPsbt, RequestError> {
        let min_feerate = FeeRate::from_sat_per_vb(min_feerate_sat_per_vb.unwrap_or_default());
        let min_feerate = max(min_feerate, self.params.min_feerate);

        let provisional_fee = self.psbt.calculate_fee();
        let provisional_weight = Weight::manual_from_u64(self.psbt.unsigned_tx.weight() as u64);
        let min_additional_fee =
            (min_feerate * provisional_weight).checked_sub(provisional_fee).unwrap_or_default();

        if min_additional_fee > bitcoin::Amount::ZERO {
            if let Some((max_additional_fee_contribution, additional_fee_output_index)) =
                self.params.additional_fee_contribution
            {
                if max_additional_fee_contribution < min_additional_fee
                    && !self.owned_vouts.contains(&additional_fee_output_index)
                {
                    // remove additional miner fee from the sender's specified output
                    self.psbt.unsigned_tx.output[additional_fee_output_index].value -=
                        min_additional_fee.to_sat();

                    // There might be excess additional fee we can take
                    // in the case a sender makes no change output
                    let excess_fee = max_additional_fee_contribution - min_additional_fee;
                    if excess_fee > bitcoin::Amount::ZERO {
                        let vout_to_augment = self
                            .owned_vouts
                            .choose(&mut rand::thread_rng())
                            .expect("owned_vouts is empty");
                        self.psbt.unsigned_tx.output[*vout_to_augment].value += excess_fee.to_sat();
                    }
                } else {
                    return Err(RequestError::from(InternalRequestError::InsufficientFee(
                        min_additional_fee,
                        self.params.additional_fee_contribution,
                    )));
                }
            }
        }

        // the payjoin proposal psbt
        let reset_psbt = UncheckedPsbt::from_unsigned_tx(self.psbt.unsigned_tx.clone())
            .expect("resetting tx failed");
        Ok(reset_psbt.into())
    }
}

/// Transaction that must be broadcasted.
#[must_use = "The transaction must be broadcasted to prevent abuse"]
pub struct MustBroadcast(pub bitcoin::Transaction);

/*
impl Proposal {
    pub fn replace_output_script(&mut self, new_output_script: Script, options: NewOutputOptions) -> Result<Self, OutputError> {
    }

    pub fn replace_output(&mut self, new_output: TxOut, options: NewOutputOptions) -> Result<Self, OutputError> {
    }

    pub fn insert_output(&mut self, new_output: TxOut, options: NewOutputOptions) -> Result<Self, OutputError> {
    }

    pub fn expected_missing_fee_for_replaced_output(&self, output_type: OutputType) -> bitcoin::Amount {
    }
}
*/

pub struct ReceiverOptions {
    dust_limit: bitcoin::Amount,
}

pub enum BumpFeePolicy {
    FailOnInsufficient,
    SubtractOurFeeOutput,
}

pub struct NewOutputOptions {
    set_as_fee_output: bool,
    subtract_fees_from_this: bool,
}

#[cfg(test)]
mod test {
    use super::*;

    struct MockHeaders {
        length: String,
    }

    impl MockHeaders {
        #[cfg(test)]
        fn new(length: u64) -> MockHeaders { MockHeaders { length: length.to_string() } }
    }

    impl Headers for MockHeaders {
        fn get_header(&self, key: &str) -> Option<&str> {
            match key {
                "content-length" => Some(&self.length),
                "content-type" => Some("text/plain"),
                _ => None,
            }
        }
    }

    fn get_proposal_from_test_vector() -> Result<UncheckedProposal, RequestError> {
        // OriginalPSBT Test Vector from BIP
        // | InputScriptType | Orginal PSBT Fee rate | maxadditionalfeecontribution | additionalfeeoutputindex|
        // |-----------------|-----------------------|------------------------------|-------------------------|
        // | P2SH-P2WPKH     |  2 sat/vbyte          | 0.00000182                   | 0                       |
        let original_psbt = "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";

        let body = original_psbt.as_bytes();
        let headers = MockHeaders::new(body.len() as u64);
        UncheckedProposal::from_request(
            body,
            "?maxadditionalfeecontribution=0.00000182?additionalfeeoutputindex=0",
            headers,
        )
    }

    #[test]
    fn can_get_proposal_from_request() {
        let proposal = get_proposal_from_test_vector();
        assert!(proposal.is_ok(), "OriginalPSBT should be a valid request");
    }

    #[test]
    fn unchecked_proposal_unlocks_after_checks() {
        use std::str::FromStr;

        use bitcoin::{Address, Network};

        let proposal = get_proposal_from_test_vector().unwrap();
        let payjoin = proposal
            .assume_interactive_receiver()
            .check_inputs_not_owned(|_| false)
            .unwrap()
            .check_no_mixed_input_scripts()
            .unwrap()
            .check_no_inputs_seen_before(|_| false)
            .unwrap()
            .identify_receiver_outputs(|script| {
                Address::from_script(script, Network::Bitcoin)
                    == Address::from_str(&"3CZZi7aWFugaCdUCS15dgrUUViupmB8bVM")
            })
            .unwrap()
            .extract_psbt(None);

        assert!(payjoin.is_ok(), "Payjoin should be a valid PSBT");
    }
}
