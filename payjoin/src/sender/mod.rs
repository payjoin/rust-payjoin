//! Send a PayJoin
//!
//! This module contains types and methods used to implement sending via BIP78.
//! Usage is pretty simple:
//!
//! 1. Parse BIP21 as [`payjoin::Uri`](crate::Uri)
//! 2. Create a finalized PSBT paying `.amount` to `.address`
//! 3. Spawn a thread or async task that will broadcast the transaction after one minute unless
//!    canceled
//! 4. Call [`PjUriExt::create_pj_request()`](crate::PjUriExt::create_pj_request()) with the PSBT and your parameters
//! 5. Send the request and receive response
//! 6. Feed the response to [`Context::process_response()`](crate::sender::Context::process_response())
//! 7. Sign resulting PSBT
//! 8. Cancel the one-minute deadline and broadcast the resulting PSBT
//!

use std::convert::TryInto;

use bitcoin::util::psbt::PartiallySignedTransaction as UncheckedPsbt;
use bitcoin::{Script, Sequence, TxOut};
pub use error::{CreateRequestError, ValidationError};
pub(crate) use error::{InternalCreateRequestError, InternalValidationError};
use url::Url;

use crate::fee_rate::FeeRate;
use crate::input_type::InputType;
use crate::psbt::Psbt;
use crate::weight::{varint_size, ComputeWeight, Weight};

// See usize casts
#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
compile_error!("This crate currently only supports 32 bit and 64 bit architectures");

mod error;

type InternalResult<T> = Result<T, InternalValidationError>;

/// Builder for sender-side payjoin parameters
///
/// These parameters define how client wants to handle PayJoin.
pub struct Params {
    disable_output_substitution: bool,
    fee_contribution: Option<(bitcoin::Amount, Option<usize>)>,
    clamp_fee_contribution: bool,
    min_fee_rate: FeeRate,
}

impl Params {
    /// Offer the receiver contribution to pay for his input.
    ///
    /// These parameters will allow the receiver to take `max_fee_contribution` from given change
    /// output to pay for additional inputs. The recommended fee is `size_of_one_input * fee_rate`.
    ///
    /// `change_index` specifies which output can be used to pay fee. I `None` is provided, then
    /// the output is auto-detected unless the supplied transaction has more than two outputs.
    pub fn with_fee_contribution(
        max_fee_contribution: bitcoin::Amount,
        change_index: Option<usize>,
    ) -> Self {
        Params {
            disable_output_substitution: false,
            fee_contribution: Some((max_fee_contribution, change_index)),
            clamp_fee_contribution: false,
            min_fee_rate: FeeRate::ZERO,
        }
    }

    /// Perform PayJoin without incentivizing the payee to cooperate.
    ///
    /// While it's generally better to offer some contribution some users may wish not to.
    /// This function disables contribution.
    pub fn non_incentivizing() -> Self {
        Params {
            disable_output_substitution: false,
            fee_contribution: None,
            clamp_fee_contribution: false,
            min_fee_rate: FeeRate::ZERO,
        }
    }

    /// Disable output substitution even if the receiver didn't.
    ///
    /// This forbids receiver switching output or decreasing amount.
    /// It is generally **not** recommended to set this as it may prevent the receiver from
    /// doing advanced operations such as opening LN channels and it also guarantees the
    /// receiver will **not** reward the sender with a discount.
    pub fn always_disable_output_substitution(mut self, disable: bool) -> Self {
        self.disable_output_substitution = disable;
        self
    }

    /// Decrease fee contribution instead of erroring.
    ///
    /// If this option is set and a transaction with change amount lower than fee
    /// contribution is provided then instead of returning error the fee contribution will
    /// be just lowered to match the change amount.
    pub fn clamp_fee_contribution(mut self, clamp: bool) -> Self {
        self.clamp_fee_contribution = clamp;
        self
    }

    /// Sets minimum fee rate required by the sender.
    pub fn min_fee_rate_sat_per_vb(mut self, fee_rate: u64) -> Self {
        self.min_fee_rate = FeeRate::from_sat_per_vb(fee_rate);
        self
    }
}

/// Represents data that needs to be transmitted to the receiver.
///
/// You need to send this request over HTTP(S) to the receiver.
#[non_exhaustive]
pub struct Request {
    /// URL to send the request to.
    ///
    /// This is full URL with scheme etc - you can pass it right to `reqwest` or a similar library.
    pub url: Url,

    /// Bytes to be sent to the receiver.
    ///
    /// This is properly encoded PSBT, already in base64. You only need to make sure `Content-Type`
    /// is `text/plain` and `Content-Length` is `body.len()` (most libraries do the latter
    /// automatically).
    pub body: Vec<u8>,
}

/// Data required for validation of response.
///
/// This type is used to process the response. It is returned from [`PjUriExt::create_pj_request()`](crate::PjUriExt::create_pj_request()) method
/// and you only need to call [`.process_response()`](crate::sender::Context::process_response()) on it to continue BIP78 flow.
pub struct Context {
    original_psbt: Psbt,
    disable_output_substitution: bool,
    fee_contribution: Option<(bitcoin::Amount, usize)>,
    min_fee_rate: FeeRate,
    input_type: InputType,
    sequence: Sequence,
    payee: Script,
}

macro_rules! check_eq {
    ($proposed:expr, $original:expr, $error:ident) => {
        match ($proposed, $original) {
            (proposed, original) if proposed != original =>
                return Err(InternalValidationError::$error { proposed, original }),
            _ => (),
        }
    };
}

macro_rules! ensure {
    ($cond:expr, $error:ident) => {
        if !($cond) {
            return Err(InternalValidationError::$error);
        }
    };
}

fn load_psbt_from_base64(
    mut input: impl std::io::Read,
) -> Result<Psbt, bitcoin::consensus::encode::Error> {
    use bitcoin::consensus::Decodable;
    let mut reader = base64::read::DecoderReader::new(&mut input, base64::STANDARD);
    Ok(UncheckedPsbt::consensus_decode(&mut reader)?
        .try_into()
        .expect("consensus_decode guarantees consistency"))
}

fn calculate_psbt_fee(psbt: &Psbt) -> bitcoin::Amount {
    let mut total_outputs = bitcoin::Amount::ZERO;
    let mut total_inputs = bitcoin::Amount::ZERO;

    for output in &psbt.unsigned_tx.output {
        total_outputs += bitcoin::Amount::from_sat(output.value);
    }

    for input in psbt.input_pairs() {
        total_inputs += bitcoin::Amount::from_sat(input.previous_txout().unwrap().value);
    }

    total_inputs - total_outputs
}

impl Context {
    /// Decodes and validates the response.
    ///
    /// Call this method with response from receiver to continue BIP78 flow. If the response is
    /// valid you will get appropriate PSBT that you should sign and broadcast.
    #[inline]
    pub fn process_response(
        self,
        response: impl std::io::Read,
    ) -> Result<UncheckedPsbt, ValidationError> {
        let proposal = load_psbt_from_base64(response).map_err(InternalValidationError::Decode)?;

        // process in non-generic function
        self.process_proposal(proposal).map(Into::into).map_err(Into::into)
    }

    fn process_proposal(self, proposal: Psbt) -> InternalResult<Psbt> {
        self.basic_checks(&proposal)?;
        let in_stats = self.check_inputs(&proposal)?;
        let out_stats = self.check_outputs(&proposal)?;
        self.check_fees(&proposal, in_stats, out_stats)?;
        Ok(proposal)
    }

    fn check_fees(
        &self,
        proposal: &Psbt,
        in_stats: InputStats,
        out_stats: OutputStats,
    ) -> InternalResult<()> {
        if out_stats.total_value > in_stats.total_value {
            return Err(InternalValidationError::Inflation);
        }
        let proposed_psbt_fee = in_stats.total_value - out_stats.total_value;
        let original_fee = calculate_psbt_fee(&self.original_psbt);
        ensure!(original_fee <= proposed_psbt_fee, AbsoluteFeeDecreased);
        ensure!(
            out_stats.contributed_fee <= proposed_psbt_fee - original_fee,
            PayeeTookContributedFee
        );
        let original_weight =
            Weight::manual_from_u64(self.original_psbt.unsigned_tx.weight() as u64);
        let original_fee_rate = original_fee / original_weight;
        ensure!(
            out_stats.contributed_fee
                <= original_fee_rate
                    * self.input_type.expected_input_weight()
                    * (proposal.inputs.len() - self.original_psbt.inputs.len()) as u64,
            FeeContributionPaysOutputSizeIncrease
        );
        if self.min_fee_rate > FeeRate::ZERO {
            let non_input_output_size =
                // version
                4 +
                // count variants
                varint_size(proposal.unsigned_tx.input.len() as u64) +
                varint_size(proposal.unsigned_tx.output.len() as u64) +
                // lock time
                4;
            let weight_without_witnesses =
                Weight::from_non_witness_data_size(non_input_output_size)
                    + in_stats.total_weight
                    + out_stats.total_weight;
            let total_weight = if in_stats.inputs_with_witnesses == 0 {
                weight_without_witnesses
            } else {
                weight_without_witnesses
                    + Weight::manual_from_u64(
                        (proposal.unsigned_tx.input.len() - in_stats.inputs_with_witnesses + 2)
                            as u64,
                    )
            };
            ensure!(proposed_psbt_fee / total_weight >= self.min_fee_rate, FeeRateBelowMinimum);
        }
        Ok(())
    }

    // version and lock time
    fn basic_checks(&self, proposal: &Psbt) -> InternalResult<()> {
        check_eq!(
            proposal.unsigned_tx.version,
            self.original_psbt.unsigned_tx.version,
            VersionsDontMatch
        );
        check_eq!(
            proposal.unsigned_tx.lock_time,
            self.original_psbt.unsigned_tx.lock_time,
            LockTimesDontMatch
        );
        Ok(())
    }

    fn check_inputs(&self, proposal: &Psbt) -> InternalResult<InputStats> {
        use crate::weight::ComputeSize;

        let mut original_inputs = self.original_psbt.input_pairs().peekable();
        let mut total_value = bitcoin::Amount::ZERO;
        let mut total_weight = Weight::ZERO;
        let mut inputs_with_witnesses = 0;

        for proposed in proposal.input_pairs() {
            ensure!(proposed.psbtin.bip32_derivation.is_empty(), TxInContainsKeyPaths);
            ensure!(proposed.psbtin.partial_sigs.is_empty(), ContainsPartialSigs);
            match original_inputs.peek() {
                // our (sender)
                Some(original)
                    if proposed.txin.previous_output == original.txin.previous_output =>
                {
                    check_eq!(
                        proposed.txin.sequence,
                        original.txin.sequence,
                        SenderTxinSequenceChanged
                    );
                    ensure!(
                        proposed.psbtin.non_witness_utxo.is_none(),
                        SenderTxinContainsNonWitnessUtxo
                    );
                    ensure!(proposed.psbtin.witness_utxo.is_none(), SenderTxinContainsWitnessUtxo);
                    ensure!(
                        proposed.psbtin.final_script_sig.is_none(),
                        SenderTxinContainsFinalScriptSig
                    );
                    ensure!(
                        proposed.psbtin.final_script_witness.is_none(),
                        SenderTxinContainsFinalScriptWitness
                    );
                    let prevout = original.previous_txout().expect("We've validated this before");
                    total_value += bitcoin::Amount::from_sat(prevout.value);
                    // We assume the signture will be the same size
                    // I know sigs can be slightly different size but there isn't much to do about
                    // it other than prefer Taproot.
                    total_weight += original.txin.weight();
                    if !original.txin.witness.is_empty() {
                        inputs_with_witnesses += 1;
                    }

                    original_inputs.next();
                }
                // theirs (receiver)
                None | Some(_) => {
                    /* this seems to be wrong but not sure why/how
                    match (&proposed.psbtin.final_script_sig, &proposed.psbtin.final_script_witness) {
                        // TODO: use to compute weight correctly
                        (Some(sig), Some(witness)) => (),
                        _ => return Err(InternalValidationError::ReceiverTxinNotFinalized)
                    }
                    */
                    let sig = proposed
                        .psbtin
                        .final_script_sig
                        .as_ref()
                        .ok_or(InternalValidationError::ReceiverTxinNotFinalized)?;
                    total_weight +=
                        Weight::from_non_witness_data_size(32 + 4 + 4 + sig.encoded_size());

                    match &proposed.psbtin.final_script_witness {
                        Some(witness) if !witness.is_empty() => {
                            inputs_with_witnesses += 1;
                            total_weight += crate::weight::witness_weight(witness);
                        }
                        _ => (),
                    }
                    ensure!(
                        proposed.psbtin.witness_utxo.is_some()
                            || proposed.psbtin.non_witness_utxo.is_some(),
                        ReceiverTxinMissingUtxoInfo
                    );
                    ensure!(proposed.txin.sequence == self.sequence, MixedSequence);
                    let txout = proposed
                        .previous_txout()
                        .map_err(InternalValidationError::InvalidProposedInput)?;
                    total_value += bitcoin::Amount::from_sat(txout.value);
                    check_eq!(
                        InputType::from_spent_input(txout, proposed.psbtin)?,
                        self.input_type,
                        MixedInputTypes
                    );
                }
            }
        }
        ensure!(original_inputs.peek().is_none(), MissingOrShuffledInputs);
        Ok(InputStats { total_value, total_weight, inputs_with_witnesses })
    }

    fn check_outputs(&self, proposal: &Psbt) -> InternalResult<OutputStats> {
        let mut original_outputs = proposal.unsigned_tx.output.iter().enumerate().peekable();
        let mut total_value = bitcoin::Amount::ZERO;
        let mut contributed_fee = bitcoin::Amount::ZERO;
        let mut total_weight = Weight::ZERO;

        for (proposed_txout, proposed_psbtout) in
            proposal.unsigned_tx.output.iter().zip(&proposal.outputs)
        {
            ensure!(proposed_psbtout.bip32_derivation.is_empty(), TxOutContainsKeyPaths);
            total_value += bitcoin::Amount::from_sat(proposed_txout.value);
            total_weight += proposed_txout.weight();
            match (original_outputs.peek(), self.fee_contribution) {
                // fee output
                (
                    Some((original_output_index, original_output)),
                    Some((max_fee_contrib, fee_contrib_idx)),
                ) if proposed_txout.script_pubkey == original_output.script_pubkey
                    && *original_output_index == fee_contrib_idx =>
                {
                    if proposed_txout.value < original_output.value {
                        contributed_fee =
                            bitcoin::Amount::from_sat(original_output.value - proposed_txout.value);
                        ensure!(contributed_fee < max_fee_contrib, FeeContributionExceedsMaximum);
                        //The remaining fee checks are done in the caller
                    }
                    original_outputs.next();
                }
                // payee output
                (Some((_original_output_index, original_output)), _)
                    if original_output.script_pubkey == self.payee =>
                {
                    ensure!(
                        !self.disable_output_substitution
                            || (proposed_txout.script_pubkey == original_output.script_pubkey
                                && proposed_txout.value >= original_output.value),
                        DisallowedOutputSubstitution
                    );
                    original_outputs.next();
                }
                // our output
                (Some((_original_output_index, original_output)), _)
                    if proposed_txout.script_pubkey == original_output.script_pubkey =>
                {
                    ensure!(proposed_txout.value >= original_output.value, OutputValueDecreased);
                    original_outputs.next();
                }
                // all original outputs processed, only additional outputs remain
                _ => (),
            }
        }

        ensure!(original_outputs.peek().is_none(), MissingOrShuffledOutputs);
        Ok(OutputStats { total_value, contributed_fee, total_weight })
    }
}

struct OutputStats {
    total_value: bitcoin::Amount,
    contributed_fee: bitcoin::Amount,
    total_weight: Weight,
}

struct InputStats {
    total_value: bitcoin::Amount,
    total_weight: Weight,
    inputs_with_witnesses: usize,
}

fn check_single_payee(
    psbt: &Psbt,
    script_pubkey: &Script,
    amount: Option<bitcoin::Amount>,
) -> Result<(), InternalCreateRequestError> {
    let mut payee_found = false;
    for output in &psbt.unsigned_tx.output {
        if output.script_pubkey == *script_pubkey {
            if let Some(amount) = amount {
                if output.value != amount.to_sat() {
                    return Err(InternalCreateRequestError::PayeeValueNotEqual);
                }
            }
            if payee_found {
                return Err(InternalCreateRequestError::MultiplePayeeOutputs);
            }
            payee_found = true;
        }
    }
    if payee_found {
        Ok(())
    } else {
        Err(InternalCreateRequestError::MissingPayeeOutput)
    }
}

fn clear_unneeded_fields(psbt: &mut Psbt) {
    psbt.xpub_mut().clear();
    psbt.proprietary_mut().clear();
    psbt.unknown_mut().clear();
    for input in psbt.inputs_mut() {
        input.bip32_derivation.clear();
        input.proprietary.clear();
        input.unknown.clear();
    }
    for output in psbt.outputs_mut() {
        output.bip32_derivation.clear();
        output.proprietary.clear();
        output.unknown.clear();
    }
}

fn check_fee_output_amount(
    output: &TxOut,
    fee: bitcoin::Amount,
    clamp_fee_contribution: bool,
) -> Result<bitcoin::Amount, InternalCreateRequestError> {
    if output.value < fee.to_sat() {
        if clamp_fee_contribution {
            Ok(bitcoin::Amount::from_sat(output.value))
        } else {
            Err(InternalCreateRequestError::FeeOutputValueLowerThanFeeContribution)
        }
    } else {
        Ok(fee)
    }
}

fn find_change_index(
    psbt: &Psbt,
    payee: &Script,
    fee: bitcoin::Amount,
    clamp_fee_contribution: bool,
) -> Result<Option<(bitcoin::Amount, usize)>, InternalCreateRequestError> {
    match (psbt.unsigned_tx.output.len(), clamp_fee_contribution) {
        (0, _) => return Err(InternalCreateRequestError::NoOutputs),
        (1, false) if psbt.unsigned_tx.output[0].script_pubkey == *payee =>
            return Err(InternalCreateRequestError::FeeOutputValueLowerThanFeeContribution),
        (1, true) if psbt.unsigned_tx.output[0].script_pubkey == *payee => return Ok(None),
        (1, _) => return Err(InternalCreateRequestError::MissingPayeeOutput),
        (2, _) => (),
        _ => return Err(InternalCreateRequestError::AmbiguousChangeOutput),
    }
    let (index, output) = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, output)| output.script_pubkey != *payee)
        .ok_or(InternalCreateRequestError::MultiplePayeeOutputs)?;

    Ok(Some((check_fee_output_amount(output, fee, clamp_fee_contribution)?, index)))
}

fn check_change_index(
    psbt: &Psbt,
    payee: &Script,
    fee: bitcoin::Amount,
    index: usize,
    clamp_fee_contribution: bool,
) -> Result<(bitcoin::Amount, usize), InternalCreateRequestError> {
    let output = psbt
        .unsigned_tx
        .output
        .get(index)
        .ok_or(InternalCreateRequestError::ChangeIndexOutOfBounds)?;
    if output.script_pubkey == *payee {
        return Err(InternalCreateRequestError::ChangeIndexPointsAtPayee);
    }
    Ok((check_fee_output_amount(output, fee, clamp_fee_contribution)?, index))
}

fn determine_fee_contribution(
    psbt: &Psbt,
    payee: &Script,
    params: &Params,
) -> Result<Option<(bitcoin::Amount, usize)>, InternalCreateRequestError> {
    Ok(match params.fee_contribution {
        Some((fee, None)) => find_change_index(psbt, payee, fee, params.clamp_fee_contribution)?,
        Some((fee, Some(index))) =>
            Some(check_change_index(psbt, payee, fee, index, params.clamp_fee_contribution)?),
        None => None,
    })
}

fn serialize_url(
    endpoint: String,
    disable_output_substitution: bool,
    fee_contribution: Option<(bitcoin::Amount, usize)>,
    min_fee_rate: FeeRate,
) -> Result<Url, url::ParseError> {
    let mut url = Url::parse(&endpoint)?;
    url.query_pairs_mut().append_pair("v", "1");
    if disable_output_substitution {
        url.query_pairs_mut().append_pair("disableoutputsubstitution", "1");
    }
    if let Some((amount, index)) = fee_contribution {
        url.query_pairs_mut()
            .append_pair("additionalfeeoutputindex", &index.to_string())
            .append_pair("maxadditionalfeecontribution", &amount.to_sat().to_string());
    }
    if min_fee_rate > FeeRate::ZERO {
        url.query_pairs_mut().append_pair("minfeerate", &min_fee_rate.to_sat_per_vb().to_string());
    }
    Ok(url)
}

fn serialize_psbt(psbt: &Psbt) -> Vec<u8> {
    use bitcoin::consensus::Encodable;

    let mut encoder = base64::write::EncoderWriter::new(Vec::new(), base64::STANDARD);
    psbt.consensus_encode(&mut encoder)
        .expect("Vec doesn't return errors in its write implementation");
    encoder.finish().expect("Vec doesn't return errors in its write implementation")
}

pub(crate) fn from_psbt_and_uri(
    mut psbt: Psbt,
    uri: crate::uri::PjUri<'_>,
    params: Params,
) -> Result<(Request, Context), CreateRequestError> {
    psbt.validate_input_utxos(true).map_err(InternalCreateRequestError::InvalidOriginalInput)?;
    let disable_output_substitution =
        uri.extras.disable_output_substitution || params.disable_output_substitution;
    let payee = uri.address.script_pubkey();

    check_single_payee(&psbt, &payee, uri.amount)?;
    let fee_contribution = determine_fee_contribution(&psbt, &payee, &params)?;
    clear_unneeded_fields(&mut psbt);

    let zeroth_input = psbt.input_pairs().next().ok_or(InternalCreateRequestError::NoInputs)?;

    let sequence = zeroth_input.txin.sequence;
    let txout = zeroth_input.previous_txout().expect("We already checked this above");
    let input_type = InputType::from_spent_input(txout, zeroth_input.psbtin).unwrap();
    let url = serialize_url(
        uri.extras.endpoint.into(),
        disable_output_substitution,
        fee_contribution,
        params.min_fee_rate,
    )
    .map_err(InternalCreateRequestError::Url)?;
    let body = serialize_psbt(&psbt);
    Ok((
        Request { url, body },
        Context {
            original_psbt: psbt,
            disable_output_substitution,
            fee_contribution,
            payee,
            input_type,
            sequence,
            min_fee_rate: params.min_fee_rate,
        },
    ))
}

#[cfg(test)]
mod tests {
    #[test]
    fn official_vectors() {
        use crate::fee_rate::FeeRate;
        use crate::input_type::{InputType, SegWitV0Type};

        let mut original_psbt = "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=".as_bytes();

        let mut proposal = "cHNidP8BAJwCAAAAAo8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////jye60aAl3JgZdaIERvjkeh72VYZuTGH/ps2I4l0IO4MBAAAAAP7///8CJpW4BQAAAAAXqRQd6EnwadJ0FQ46/q6NcutaawlEMIcACT0AAAAAABepFHdAltvPSGdDwi9DR+m0af6+i2d6h9MAAAAAAQEgqBvXBQAAAAAXqRTeTh6QYcpZE1sDWtXm1HmQRUNU0IcBBBYAFMeKRXJTVYKNVlgHTdUmDV/LaYUwIgYDFZrAGqDVh1TEtNi300ntHt/PCzYrT2tVEGcjooWPhRYYSFzWUDEAAIABAACAAAAAgAEAAAAAAAAAAAEBIICEHgAAAAAAF6kUyPLL+cphRyyI5GTUazV0hF2R2NWHAQcXFgAUX4BmVeWSTJIEwtUb5TlPS/ntohABCGsCRzBEAiBnu3tA3yWlT0WBClsXXS9j69Bt+waCs9JcjWtNjtv7VgIge2VYAaBeLPDB6HGFlpqOENXMldsJezF9Gs5amvDQRDQBIQJl1jz1tBt8hNx2owTm+4Du4isx0pmdKNMNIjjaMHFfrQABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUIgICygvBWB5prpfx61y1HDAwo37kYP3YRJBvAjtunBAur3wYSFzWUDEAAIABAACAAAAAgAEAAAABAAAAAAA=".as_bytes();

        let original_psbt = super::load_psbt_from_base64(&mut original_psbt).unwrap();
        eprintln!("original: {:#?}", original_psbt);
        let payee = original_psbt.unsigned_tx.output[1].script_pubkey.clone();
        let sequence = original_psbt.unsigned_tx.input[0].sequence;
        let ctx = super::Context {
            original_psbt,
            disable_output_substitution: false,
            fee_contribution: None,
            min_fee_rate: FeeRate::ZERO,
            payee,
            input_type: InputType::SegWitV0 { ty: SegWitV0Type::Pubkey, nested: true },
            sequence,
        };
        let mut proposal = super::load_psbt_from_base64(&mut proposal).unwrap();
        eprintln!("proposal: {:#?}", proposal);
        for output in proposal.outputs_mut() {
            output.bip32_derivation.clear();
        }
        for input in proposal.inputs_mut() {
            input.bip32_derivation.clear();
        }
        proposal.inputs_mut()[0].witness_utxo = None;
        ctx.process_proposal(proposal).unwrap();
    }
}
