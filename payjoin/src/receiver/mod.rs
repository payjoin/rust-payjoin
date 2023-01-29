use std::convert::TryFrom;

use bitcoin::util::psbt::PartiallySignedTransaction as UncheckedPsbt;
use bitcoin::{AddressType, OutPoint, Script, TxOut};

mod error;
mod optional_parameters;

use error::InternalRequestError;
pub use error::RequestError;
use optional_parameters::Params;

use crate::psbt::Psbt;

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
    pub fn get_transaction_to_check_broadcast(&self) -> bitcoin::Transaction {
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
    pub fn assume_tested_and_scheduled_broadcast(self) -> MaybeInputsOwned {
        MaybeInputsOwned { psbt: self.psbt, params: self.params }
    }

    /// Call this method if the only way to initiate a PayJoin with this receiver
    /// requires manual intervention, as in most consumer wallets.
    ///
    /// So-called "non-interactive" receivers, like payment processors, that allow arbitrary requests are otherwise vulnerable to probing attacks.
    /// Those receivers call `get_transaction_to_check_broadcast()` and `attest_tested_and_scheduled_broadcast()` after making those checks downstream.
    pub fn assume_interactive_receive_endpoint(self) -> MaybeInputsOwned {
        MaybeInputsOwned { psbt: self.psbt, params: self.params }
    }
}

impl MaybeInputsOwned {
    /// The receiver should not be able to sign for any of these Original PSBT inputs.
    ///
    /// Check that none of them are owned by the receiver downstream before proceeding.
    pub fn iter_input_script_pubkeys(&self) -> Vec<Result<&Script, RequestError>> {
        todo!() // return impl '_ + Iterator<Item = Result<&Script, RequestError>>
    }

    /// Check that the Original PSBT has no receiver-owned inputs.
    /// Return original-psbt-rejected error or otherwise refuse to sign undesirable inputs.
    ///
    /// An attacker could try to spend receiver's own inputs. This check prevents that.
    /// Call this after checking downstream.
    pub fn assume_inputs_not_owned(self) -> MaybeMixedInputScripts {
        MaybeMixedInputScripts { psbt: self.psbt, params: self.params }
    }
}

impl MaybeMixedInputScripts {
    /// If there is only 1 input type, the receiver should be able to produce the same
    /// type.
    ///
    /// Check downstream before proceeding.
    pub fn iter_input_script_types(&self) -> Vec<Result<&AddressType, RequestError>> {
        todo!() // return Iterator<Item = Result<&AddressType, RequestError>>
    }

    /// Verify the original transaction did not have mixed input types
    /// Call this after checking downstream.
    ///
    /// Note: mixed spends do not necessarily indicate distinct wallet fingerprints.
    /// This check is intended to prevent some types of wallet fingerprinting.
    pub fn assume_no_mixed_input_scripts(self) -> MaybeInputsSeen {
        MaybeInputsSeen { psbt: self.psbt, params: self.params }
    }
}

impl MaybeInputsSeen {
    /// The receiver should not have sent to or received the Original PSBT's inputs before.
    ///
    /// Check that these are unknown, never before seen inputs before proceeding.
    pub fn iter_input_outpoints(&self) -> impl '_ + Iterator<Item = &bitcoin::OutPoint> {
        self.psbt.unsigned_tx.input.iter().map(|input| &input.previous_output)
    }

    /// Make sure that the original transaction inputs have never been seen before.
    /// This prevents probing attacks. This prevents reentrant PayJoin, where a sender
    /// proposes a PayJoin PSBT as a new Original PSBT for a new PayJoin.
    ///
    /// Call this after checking downstream.
    pub fn assume_no_inputs_seen_before(self) -> PayjoinProposal {
        PayjoinProposal::new(self.psbt, self.params)
    }
}

pub struct PayjoinProposal {
    psbt: Psbt,
    params: Params,
    owned_vout: usize,
}

impl PayjoinProposal {
    /// Initialize a Payjoin Proposal PSBT by clearing it for receiver contribution
    fn new(mut original_psbt: Psbt, params: Params) -> Self {
        // empty original_psbt signatures because we won't broadcast the original_psbt
        // we already extracted a valid one past [`UncheckedProposal`]
        original_psbt
            .unsigned_tx
            .input
            .iter_mut()
            .for_each(|txin| txin.script_sig = bitcoin::Script::default());
        // Remove vestigial invalid signature data from the Original PSBT
        // TODO test necessity
        let unchecked_original_psbt =
            UncheckedPsbt::from_unsigned_tx(original_psbt.unsigned_tx.clone())
                .expect("resetting tx failed");
        let original_psbt = Psbt::try_from(unchecked_original_psbt)
            .expect("already checked in from_request. Should not fail.");

        // TODO identify and maintain payment / transfer vout(s) or output(s)
        // ⚠️ safety critical to replace this (just assume 0 for now) ⚠️
        Self { psbt: original_psbt, params, owned_vout: 0 }
    }

    pub fn utxos_to_be_locked(&self) -> impl '_ + Iterator<Item = &bitcoin::OutPoint> {
        self.psbt.unsigned_tx.input.iter().map(|input| &input.previous_output)
    }

    pub fn psbt(self) -> UncheckedPsbt { self.psbt.into() }

    pub fn is_output_substitution_disabled(&self) -> bool {
        self.params.disable_output_substitution
    }

    pub fn contribute_new_input(&mut self, txo: TxOut, outpoint: OutPoint) {
        // The payjoin proposal must not introduce mixed input sequence numbers
        let original_sequence =
            self.psbt.unsigned_tx.input.first().map(|input| input.sequence).unwrap_or_default();

        // Add the value of new receiver input to receiver output
        let txo_value = txo.value;
        self.psbt.unsigned_tx.output[self.owned_vout].value += txo_value;

        self.psbt
            .inputs
            .push(bitcoin::psbt::Input { witness_utxo: Some(txo), ..Default::default() });
        self.psbt.unsigned_tx.input.push(bitcoin::TxIn {
            previous_output: outpoint,
            sequence: original_sequence,
            ..Default::default()
        });
    }

    /// Just replace an output address with
    pub fn substitute_output_address(&mut self, substitute_address: bitcoin::Address) {
        self.psbt.unsigned_tx.output[self.owned_vout].script_pubkey =
            substitute_address.script_pubkey();
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
        let proposal = get_proposal_from_test_vector().unwrap();
        let unlocked = proposal
            .assume_tested_and_scheduled_broadcast()
            .assume_inputs_not_owned()
            .assume_no_mixed_input_scripts()
            .assume_no_inputs_seen_before();
    }
}
