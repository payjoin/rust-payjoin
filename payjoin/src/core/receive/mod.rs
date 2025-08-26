//! Receive Payjoin
//!
//! This module contains types and methods used to implement receiving via Payjoin.
//!
//! For most use cases, we recommended enabling the `v2` feature, as it is
//! backwards compatible and provides the most convenient experience for users and implementers.
//! To use version 2, refer to `receive::v2` module documentation.
//!
//! If you specifically need to use
//! version 1, refer to the `receive::v1` module documentation after enabling the `v1` feature.

use std::collections::BTreeMap;
use std::str::FromStr;

use bitcoin::hashes::sha256d::Hash;
use bitcoin::secp256k1::rand::seq::SliceRandom;
use bitcoin::secp256k1::rand::{self, Rng};
use bitcoin::{
    psbt, AddressType, FeeRate, OutPoint, Psbt, Script, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Weight,
};
pub(crate) use error::InternalPayloadError;
pub use error::{
    Error, InputContributionError, JsonReply, OutputSubstitutionError, PayloadError,
    ReplyableError, SelectionError,
};
use optional_parameters::Params;
use serde::{Deserialize, Serialize};

pub use crate::psbt::PsbtInputError;
use crate::psbt::{
    InputWeightError, InternalInputPair, InternalPsbtInputError, PrevTxOutError, PsbtExt,
};
use crate::receive::error::InternalOutputSubstitutionError;
use crate::{ImplementationError, Version};

mod error;
pub(crate) mod optional_parameters;

#[cfg(feature = "v1")]
#[cfg_attr(docsrs, doc(cfg(feature = "v1")))]
pub mod v1;
#[cfg(not(feature = "v1"))]
pub(crate) mod v1;

#[cfg(feature = "v2")]
#[cfg_attr(docsrs, doc(cfg(feature = "v2")))]
pub mod v2;

/// A pair of ([`TxIn`], [`psbt::Input`]) with some built-in validation.
///
/// Use with [`InputPair::new`] to contribute receiver inputs.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InputPair {
    pub(crate) txin: TxIn,
    pub(crate) psbtin: psbt::Input,
    pub(crate) expected_weight: Weight,
}

impl InputPair {
    /// Creates a new InputPair while validating that the passed [`TxIn`] and [`psbt::Input`]
    /// refer to the same and the correct UTXO.
    pub fn new(
        txin: TxIn,
        psbtin: psbt::Input,
        expected_weight: Option<Weight>,
    ) -> Result<Self, PsbtInputError> {
        let raw = InternalInputPair { txin: &txin, psbtin: &psbtin };
        raw.validate_utxo()?;

        let expected_weight = match (raw.expected_input_weight(), expected_weight) {
            (Ok(_), Some(_)) => {
                return Err(InternalPsbtInputError::ProvidedUnnecessaryWeight.into());
            }
            (Ok(weight), None) => weight,
            (Err(InputWeightError::NotSupported), Some(expected_weight)) => expected_weight,
            (Err(e), _) => return Err(InternalPsbtInputError::from(e).into()),
        };

        let input_pair = Self { expected_weight, txin, psbtin };
        Ok(input_pair)
    }

    /// Helper function for creating legacy input pairs
    fn new_legacy_input_pair(
        non_witness_utxo: Transaction,
        outpoint: OutPoint,
        sequence: Option<Sequence>,
        redeem_script: Option<ScriptBuf>,
    ) -> Result<Self, PsbtInputError> {
        let txin = TxIn {
            previous_output: OutPoint { txid: outpoint.txid, vout: outpoint.vout },
            script_sig: Default::default(),
            sequence: sequence.unwrap_or_default(),
            witness: Default::default(),
        };

        let psbtin = psbt::Input {
            non_witness_utxo: Some(non_witness_utxo),
            redeem_script,
            ..psbt::Input::default()
        };

        Self::new(txin, psbtin, None)
    }

    fn get_txout_for_outpoint(
        utxo: &Transaction,
        outpoint: OutPoint,
    ) -> Result<&TxOut, PsbtInputError> {
        if let Some(txout) = utxo.output.get(usize::try_from(outpoint.vout).map_err(|_| {
            InternalPsbtInputError::PrevTxOut(PrevTxOutError::IndexOutOfBounds {
                index: outpoint.vout,
                output_count: utxo.output.len(),
            })
        })?) {
            Ok(txout)
        } else {
            Err(InternalPsbtInputError::PrevTxOut(PrevTxOutError::IndexOutOfBounds {
                index: outpoint.vout,
                output_count: utxo.output.len(),
            })
            .into())
        }
    }

    /// Constructs a new [`InputPair`] for spending a legacy P2PKH output.
    pub fn new_p2pkh(
        non_witness_utxo: Transaction,
        outpoint: OutPoint,
        sequence: Option<Sequence>,
    ) -> Result<Self, PsbtInputError> {
        let txout = Self::get_txout_for_outpoint(&non_witness_utxo, outpoint)?;
        if !txout.script_pubkey.is_p2pkh() {
            return Err(InternalPsbtInputError::InvalidScriptPubKey(AddressType::P2pkh).into());
        }
        Self::new_legacy_input_pair(non_witness_utxo, outpoint, sequence, None)
    }

    /// Constructs a new [`InputPair`] for spending a legacy P2SH output.
    pub fn new_p2sh(
        non_witness_utxo: Transaction,
        outpoint: OutPoint,
        redeem_script: ScriptBuf,
        sequence: Option<Sequence>,
    ) -> Result<Self, PsbtInputError> {
        let txout = Self::get_txout_for_outpoint(&non_witness_utxo, outpoint)?;
        if !txout.script_pubkey.is_p2sh() {
            return Err(InternalPsbtInputError::InvalidScriptPubKey(AddressType::P2sh).into());
        }
        Self::new_legacy_input_pair(non_witness_utxo, outpoint, sequence, Some(redeem_script))
    }

    /// Helper function for creating SegWit input pairs
    fn new_segwit_input_pair(
        txout: TxOut,
        outpoint: OutPoint,
        sequence: Option<Sequence>,
        expected_weight: Option<Weight>,
    ) -> Result<Self, PsbtInputError> {
        let txin = TxIn {
            previous_output: OutPoint { txid: outpoint.txid, vout: outpoint.vout },
            script_sig: Default::default(),
            sequence: sequence.unwrap_or_default(),
            witness: Default::default(),
        };

        let psbtin = psbt::Input {
            witness_utxo: Some(TxOut { value: txout.value, script_pubkey: txout.script_pubkey }),
            ..psbt::Input::default()
        };

        Self::new(txin, psbtin, expected_weight)
    }

    /// Constructs a new [`InputPair`] for spending a native SegWit P2WPKH output.
    pub fn new_p2wpkh(
        txout: TxOut,
        outpoint: OutPoint,
        sequence: Option<Sequence>,
    ) -> Result<Self, PsbtInputError> {
        if !txout.script_pubkey.is_p2wpkh() {
            return Err(InternalPsbtInputError::InvalidScriptPubKey(AddressType::P2wpkh).into());
        }

        Self::new_segwit_input_pair(txout, outpoint, sequence, None)
    }

    /// Constructs a new [`InputPair`] for spending a native SegWit P2WSH output.
    pub fn new_p2wsh(
        txout: TxOut,
        outpoint: OutPoint,
        sequence: Option<Sequence>,
        expected_weight: Weight,
    ) -> Result<Self, PsbtInputError> {
        if !txout.script_pubkey.is_p2wsh() {
            return Err(InternalPsbtInputError::InvalidScriptPubKey(AddressType::P2wsh).into());
        }

        Self::new_segwit_input_pair(txout, outpoint, sequence, Some(expected_weight))
    }

    /// Constructs a new [`InputPair`] for spending a native SegWit P2TR output.
    pub fn new_p2tr(
        txout: TxOut,
        outpoint: OutPoint,
        sequence: Option<Sequence>,
    ) -> Result<Self, PsbtInputError> {
        if !txout.script_pubkey.is_p2tr() {
            return Err(InternalPsbtInputError::InvalidScriptPubKey(AddressType::P2tr).into());
        }

        Self::new_segwit_input_pair(txout, outpoint, sequence, None)
    }

    pub(crate) fn previous_txout(&self) -> TxOut {
        InternalInputPair::from(self)
            .previous_txout()
            .expect("UTXO information should have been validated in InputPair::new")
            .clone()
    }
}

impl<'a> From<&'a InputPair> for InternalInputPair<'a> {
    fn from(pair: &'a InputPair) -> Self { Self { psbtin: &pair.psbtin, txin: &pair.txin } }
}

/// Validate the payload of a Payjoin request for PSBT and Params sanity
pub(crate) fn parse_payload(
    base64: &str,
    query: &str,
    supported_versions: &'static [Version],
) -> Result<(Psbt, Params), PayloadError> {
    let unchecked_psbt = Psbt::from_str(base64).map_err(InternalPayloadError::ParsePsbt)?;

    let psbt = unchecked_psbt.validate().map_err(InternalPayloadError::InconsistentPsbt)?;
    log::debug!("Received original psbt: {psbt:?}");

    let pairs = url::form_urlencoded::parse(query.as_bytes());
    let params = Params::from_query_pairs(pairs, supported_versions)
        .map_err(InternalPayloadError::SenderParams)?;
    log::debug!("Received request with params: {params:?}");

    Ok((psbt, params))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PsbtContext {
    original_psbt: Psbt,
    pub(crate) payjoin_psbt: Psbt,
}

impl PsbtContext {
    /// Prepare the PSBT by creating a new PSBT and copying only the fields allowed by the [spec](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#senders-payjoin-proposal-checklist)
    fn prepare_psbt(self, processed_psbt: Psbt) -> Psbt {
        log::trace!("Original PSBT from callback: {processed_psbt:#?}");

        // Create a new PSBT and copy only the allowed fields
        let mut filtered_psbt = Psbt {
            unsigned_tx: processed_psbt.unsigned_tx,
            version: processed_psbt.version,
            xpub: BTreeMap::new(),
            proprietary: BTreeMap::new(),
            unknown: BTreeMap::new(),
            inputs: vec![],
            outputs: vec![],
        };

        for input in &processed_psbt.inputs {
            filtered_psbt.inputs.push(bitcoin::psbt::Input {
                witness_utxo: input.witness_utxo.clone(),
                non_witness_utxo: input.non_witness_utxo.clone(),
                sighash_type: input.sighash_type,
                final_script_sig: input.final_script_sig.clone(),
                final_script_witness: input.final_script_witness.clone(),
                tap_key_sig: input.tap_key_sig,
                tap_script_sigs: input.tap_script_sigs.clone(),
                tap_merkle_root: input.tap_merkle_root,
                ..Default::default()
            });
        }

        for _ in &processed_psbt.outputs {
            filtered_psbt.outputs.push(bitcoin::psbt::Output::default());
        }

        log::trace!("Filtered PSBT: {filtered_psbt:#?}");

        filtered_psbt
    }

    /// Return the indexes of the sender inputs.
    fn sender_input_indexes(&self) -> Vec<usize> {
        // iterate proposal as mutable WITH the outpoint (previous_output) available too
        let mut original_inputs = self.original_psbt.input_pairs().peekable();
        let mut sender_input_indexes = vec![];
        for (i, input) in self.payjoin_psbt.input_pairs().enumerate() {
            if let Some(original) = original_inputs.peek() {
                log::trace!(
                    "match previous_output: {} == {}",
                    input.txin.previous_output,
                    original.txin.previous_output
                );
                if input.txin.previous_output == original.txin.previous_output {
                    sender_input_indexes.push(i);
                    original_inputs.next();
                }
            }
        }
        sender_input_indexes
    }

    /// Finalizes the Payjoin proposal into a PSBT which the sender will find acceptable before
    /// they sign the transaction and broadcast it to the network.
    ///
    /// Finalization consists of two steps:
    ///   1. Remove all sender signatures which were received with the original PSBT as these signatures are now invalid.
    ///   2. Sign and finalize the resulting PSBT using the passed `wallet_process_psbt` signing function.
    pub(crate) fn finalize_proposal(
        self,
        wallet_process_psbt: impl Fn(&Psbt) -> Result<Psbt, ImplementationError>,
    ) -> Result<Psbt, FinalizeProposalError> {
        let mut psbt = self.payjoin_psbt.clone();
        // Remove now-invalid sender signatures before applying the receiver signatures
        for i in self.sender_input_indexes() {
            log::trace!("Clearing sender input {i}");
            psbt.inputs[i].final_script_sig = None;
            psbt.inputs[i].final_script_witness = None;
            psbt.inputs[i].tap_key_sig = None;
        }
        let finalized_psbt =
            wallet_process_psbt(&psbt).map_err(FinalizeProposalError::Implementation)?;
        let expected_ntxid = self.payjoin_psbt.unsigned_tx.compute_ntxid();
        let actual_ntxid = finalized_psbt.unsigned_tx.compute_ntxid();
        if expected_ntxid != actual_ntxid {
            return Err(FinalizeProposalError::NtxidMismatch(expected_ntxid, actual_ntxid));
        }
        let payjoin_proposal = self.prepare_psbt(finalized_psbt);
        Ok(payjoin_proposal)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FinalizeProposalError {
    /// The ntxid of the original PSBT does not match the ntxid of the finalized PSBT.
    NtxidMismatch(Hash, Hash),
    /// The implementation of the `wallet_process_psbt` function returned an error.
    Implementation(ImplementationError),
}

impl std::fmt::Display for FinalizeProposalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NtxidMismatch(expected, actual) => {
                write!(f, "Ntxid mismatch: expected {expected}, got {actual}")
            }
            Self::Implementation(e) => write!(f, "Implementation error: {e}"),
        }
    }
}

impl std::error::Error for FinalizeProposalError {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Original {
    pub(crate) psbt: Psbt,
    pub(crate) params: Params,
}

impl Original {
    // Calculates the fee rate of the original proposal PSBT.
    fn psbt_fee_rate(&self) -> Result<FeeRate, InternalPayloadError> {
        let original_psbt_fee = self.psbt.fee().map_err(|e| {
            InternalPayloadError::ParsePsbt(bitcoin::psbt::PsbtParseError::PsbtEncoding(e))
        })?;
        Ok(original_psbt_fee / self.psbt.clone().extract_tx_unchecked_fee_rate().weight())
    }

    pub fn check_broadcast_suitability(
        &self,
        min_fee_rate: Option<FeeRate>,
        can_broadcast: impl Fn(&bitcoin::Transaction) -> Result<bool, ImplementationError>,
    ) -> Result<(), ReplyableError> {
        let original_psbt_fee_rate = self.psbt_fee_rate()?;
        if let Some(min_fee_rate) = min_fee_rate {
            if original_psbt_fee_rate < min_fee_rate {
                return Err(InternalPayloadError::PsbtBelowFeeRate(
                    original_psbt_fee_rate,
                    min_fee_rate,
                )
                .into());
            }
        }
        if can_broadcast(&self.psbt.clone().extract_tx_unchecked_fee_rate())
            .map_err(ReplyableError::Implementation)?
        {
            Ok(())
        } else {
            Err(InternalPayloadError::OriginalPsbtNotBroadcastable.into())
        }
    }

    /// Check that the original PSBT has no receiver-owned inputs.
    ///
    /// An attacker can try to spend the receiver's own inputs. This check prevents that.
    pub fn check_inputs_not_owned(
        &self,
        is_owned: &mut impl FnMut(&Script) -> Result<bool, ImplementationError>,
    ) -> Result<(), ReplyableError> {
        let mut err: Result<(), ReplyableError> = Ok(());
        if let Some(e) = self
            .psbt
            .input_pairs()
            .scan(&mut err, |err, input| match input.previous_txout() {
                Ok(txout) => Some(txout.script_pubkey.to_owned()),
                Err(e) => {
                    **err = Err(InternalPayloadError::PrevTxOut(e).into());
                    None
                }
            })
            .find_map(|script| match is_owned(&script) {
                Ok(false) => None,
                Ok(true) => Some(InternalPayloadError::InputOwned(script).into()),
                Err(e) => Some(ReplyableError::Implementation(e)),
            })
        {
            return Err(e);
        }
        err?;
        Ok(())
    }

    pub fn check_no_inputs_seen_before(
        &self,
        is_known: &mut impl FnMut(&OutPoint) -> Result<bool, ImplementationError>,
    ) -> Result<(), ReplyableError> {
        self.psbt.input_pairs().try_for_each(|input| {
            match is_known(&input.txin.previous_output) {
                Ok(false) => Ok::<(), ReplyableError>(()),
                Ok(true) =>  {
                    log::warn!("Request contains an input we've seen before: {}. Preventing possible probing attack.", input.txin.previous_output);
                    Err(InternalPayloadError::InputSeen(input.txin.previous_output))?
                },
                Err(e) => Err(ReplyableError::Implementation(e))?,
            }
        })?;
        Ok(())
    }

    pub fn identify_receiver_outputs(
        &self,
        is_receiver_output: &mut impl FnMut(&Script) -> Result<bool, ImplementationError>,
    ) -> Result<Vec<usize>, ReplyableError> {
        let owned_vouts: Vec<usize> = self
            .psbt
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .filter_map(|(vout, txo)| match is_receiver_output(&txo.script_pubkey) {
                Ok(true) => Some(Ok(vout)),
                Ok(false) => None,
                Err(e) => Some(Err(e)),
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(ReplyableError::Implementation)?;

        if owned_vouts.is_empty() {
            return Err(InternalPayloadError::MissingPayment.into());
        }

        let mut params = self.params.clone();
        if let Some((_, additional_fee_output_index)) = params.additional_fee_contribution {
            // If the additional fee output index specified by the sender is pointing to a receiver output,
            // the receiver should ignore the parameter.
            if owned_vouts.contains(&additional_fee_output_index) {
                params.additional_fee_contribution = None;
            }
        }

        Ok(owned_vouts)
    }
}

/// Shuffles `new` vector, then interleaves its elements with those from `original`,
/// maintaining the relative order in `original` but randomly inserting elements from `new`.
///
/// The combined result replaces the contents of `original`.
fn interleave_shuffle<T: Clone, R: rand::Rng>(original: &mut Vec<T>, new: &mut [T], rng: &mut R) {
    // Shuffle the substitute_outputs
    new.shuffle(rng);
    // Create a new vector to store the combined result
    let mut combined = Vec::with_capacity(original.len() + new.len());
    // Initialize indices
    let mut original_index = 0;
    let mut new_index = 0;
    // Interleave elements
    while original_index < original.len() || new_index < new.len() {
        if original_index < original.len() && (new_index >= new.len() || rng.gen_bool(0.5)) {
            combined.push(original[original_index].clone());
            original_index += 1;
        } else {
            combined.push(new[new_index].clone());
            new_index += 1;
        }
    }
    *original = combined;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WantsOutputs {
    original_psbt: Psbt,
    payjoin_psbt: Psbt,
    params: Params,
    change_vout: usize,
    owned_vouts: Vec<usize>,
}

impl WantsOutputs {
    pub(crate) fn from_original(original: Original, owned_vouts: Vec<usize>) -> Self {
        Self {
            original_psbt: original.psbt.clone(),
            payjoin_psbt: original.psbt,
            params: original.params,
            change_vout: owned_vouts[0],
            owned_vouts,
        }
    }

    /// Returns whether the receiver is allowed to substitute original outputs or not.
    pub(crate) fn output_substitution(&self) -> crate::OutputSubstitution {
        self.params.output_substitution
    }
    /// Substitute the receiver output script with the provided script.
    pub(crate) fn substitute_receiver_script(
        &self,
        output_script: &Script,
    ) -> Result<Self, OutputSubstitutionError> {
        let output_value = self.original_psbt.unsigned_tx.output[self.change_vout].value;
        let outputs = [TxOut { value: output_value, script_pubkey: output_script.into() }];
        self.replace_receiver_outputs(outputs, output_script)
    }

    /// Replaces **all** receiver outputs with the one or more provided `replacement_outputs`, and
    /// sets up the passed `drain_script` as the receiver-owned output which might have its value
    /// adjusted based on the modifications the receiver makes in the subsequent typestates.
    ///
    /// The sender's outputs are not touched. Existing receiver outputs will be replaced with the
    /// outputs in the `replacement_outputs` argument. The number of replacement outputs should
    /// match or exceed the number of receiver outputs in the original proposal PSBT.
    ///
    /// The drain script is the receiver script which will have its value adjusted based on the
    /// modifications the receiver makes on the transaction in the subsequent typestates. For
    /// example, if the receiver adds their own input, then the drain script output will have its
    /// value increased by the same amount. Or if an output needs to have its value reduced to
    /// account for fees, the value of the output for this script will be reduced.
    pub(crate) fn replace_receiver_outputs(
        &self,
        replacement_outputs: impl IntoIterator<Item = TxOut>,
        drain_script: &Script,
    ) -> Result<Self, OutputSubstitutionError> {
        let mut payjoin_psbt = self.original_psbt.clone();
        let mut outputs = vec![];
        let mut replacement_outputs: Vec<TxOut> = replacement_outputs.into_iter().collect();
        let mut rng = rand::thread_rng();
        // Substitute the existing receiver outputs, keeping the sender/receiver output ordering
        for (i, original_output) in self.original_psbt.unsigned_tx.output.iter().enumerate() {
            if self.owned_vouts.contains(&i) {
                // Receiver output: substitute in-place a provided replacement output
                if replacement_outputs.is_empty() {
                    return Err(InternalOutputSubstitutionError::NotEnoughOutputs.into());
                }
                match replacement_outputs
                    .iter()
                    .position(|txo| txo.script_pubkey == original_output.script_pubkey)
                {
                    // Select an output with the same address if one was provided
                    Some(pos) => {
                        let txo = replacement_outputs.swap_remove(pos);
                        #[cfg(feature = "v1")]
                        if self.output_substitution() == crate::OutputSubstitution::Disabled
                            && txo.value < original_output.value
                        {
                            return Err(
                                InternalOutputSubstitutionError::DecreasedValueWhenDisabled.into(),
                            );
                        }
                        outputs.push(txo);
                    }
                    // Otherwise randomly select one of the replacement outputs
                    None => {
                        #[cfg(feature = "v1")]
                        if self.output_substitution() == crate::OutputSubstitution::Disabled {
                            return Err(
                                InternalOutputSubstitutionError::ScriptPubKeyChangedWhenDisabled
                                    .into(),
                            );
                        }
                        let index = rng.gen_range(0..replacement_outputs.len());
                        let txo = replacement_outputs.swap_remove(index);
                        outputs.push(txo);
                    }
                }
            } else {
                // Sender output: leave it as is
                outputs.push(original_output.clone());
            }
        }
        // Insert all remaining outputs at random indices for privacy
        interleave_shuffle(&mut outputs, &mut replacement_outputs, &mut rng);
        // Identify the receiver output that will be used for change and fees
        let change_vout = outputs.iter().position(|txo| txo.script_pubkey == *drain_script);
        // Update the payjoin PSBT outputs
        payjoin_psbt.outputs = vec![Default::default(); outputs.len()];
        payjoin_psbt.unsigned_tx.output = outputs;
        Ok(Self {
            original_psbt: self.original_psbt.clone(),
            payjoin_psbt,
            params: self.params.clone(),
            change_vout: change_vout.ok_or(InternalOutputSubstitutionError::InvalidDrainScript)?,
            owned_vouts: self.owned_vouts.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::{LockTime, Time};
    use bitcoin::hashes::Hash;
    use bitcoin::key::{PublicKey, WPubkeyHash};
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::transaction::InputWeightPrediction;
    use bitcoin::{
        witness, Amount, PubkeyHash, ScriptBuf, ScriptHash, Txid, WScriptHash, XOnlyPublicKey,
    };
    use payjoin_test_utils::{DUMMY20, DUMMY32};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use super::*;
    use crate::psbt::InternalPsbtInputError::InvalidScriptPubKey;

    // TODO: this is duplicated in a couple places. In these tests, receiver, and the sender.
    // We should pub(crate) it and moved to a common place.
    const NON_WITNESS_DATA_WEIGHT: Weight = Weight::from_non_witness_data_size(32 + 4 + 4);

    #[test]
    fn input_pair_with_expected_weight() {
        let p2wsh_txout = TxOut {
            value: Amount::from_sat(123),
            script_pubkey: ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array(DUMMY32)),
        };
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::Seconds(Time::MIN),
            input: vec![],
            output: vec![p2wsh_txout.clone()],
        };
        let expected_satifiability_weight = Weight::from_wu(42);

        let previous_output = OutPoint { txid: tx.compute_txid(), vout: 0 };
        let input_pair = InputPair::new(
            TxIn { previous_output, sequence: Sequence::MAX, ..Default::default() },
            psbt::Input { witness_utxo: Some(p2wsh_txout), ..Default::default() },
            Some(expected_satifiability_weight),
        )
        .unwrap();

        assert_eq!(input_pair.expected_weight, expected_satifiability_weight);
    }

    #[test]
    fn create_p2pkh_input_pair() {
        let p2sh_txout = TxOut {
            value: Amount::from_sat(123),
            script_pubkey: ScriptBuf::new_p2sh(&ScriptHash::from_byte_array(DUMMY20)),
        };

        // With vout = 1, this is the TxOut that's being validated as p2pkh
        let p2pkh_txout = TxOut {
            value: Amount::from_sat(456),
            script_pubkey: ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(DUMMY20)),
        };
        let utxo = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: LockTime::Seconds(Time::MIN),
            input: vec![],
            output: vec![p2sh_txout, p2pkh_txout],
        };
        let outpoint = OutPoint { txid: utxo.compute_txid(), vout: 1 };
        let sequence = Sequence::from_512_second_intervals(123);

        let p2pkh_pair = InputPair::new_p2pkh(utxo.clone(), outpoint, Some(sequence)).unwrap();
        assert_eq!(p2pkh_pair.txin.previous_output, outpoint);
        assert_eq!(p2pkh_pair.txin.sequence, sequence);
        assert_eq!(p2pkh_pair.psbtin.non_witness_utxo.unwrap(), utxo);
        assert_eq!(
            p2pkh_pair.expected_weight,
            InputWeightPrediction::P2PKH_COMPRESSED_MAX.weight() + NON_WITNESS_DATA_WEIGHT
        );

        // Failures
        let utxo_with_p2sh = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: LockTime::Seconds(Time::MIN),
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(123),
                script_pubkey: ScriptBuf::new_p2sh(&ScriptHash::from_byte_array(DUMMY20)),
            }],
        };
        let outpoint = OutPoint { txid: utxo_with_p2sh.compute_txid(), vout: 0 };
        let invalid_p2pkh_pair = InputPair::new_p2pkh(utxo_with_p2sh.clone(), outpoint, None);
        assert_eq!(
            invalid_p2pkh_pair.err().unwrap(),
            PsbtInputError::from(InvalidScriptPubKey(AddressType::P2pkh))
        );

        let utxo_empty_outputs = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: LockTime::Seconds(Time::MIN),
            input: vec![],
            output: vec![],
        };
        let outpoint = OutPoint { txid: utxo_empty_outputs.compute_txid(), vout: 0 };
        let invalid_p2pkh_pair = InputPair::new_p2pkh(utxo_empty_outputs.clone(), outpoint, None);
        assert_eq!(
            invalid_p2pkh_pair.err().unwrap(),
            PsbtInputError::from(InternalPsbtInputError::PrevTxOut(
                PrevTxOutError::IndexOutOfBounds { index: outpoint.vout, output_count: 0 }
            ))
        );
    }

    #[test]
    fn create_p2sh_input_pair() {
        // With vout = 0, this is the TxOut that's being validated as p2sh
        let p2sh_txout = TxOut {
            value: Amount::from_sat(123),
            script_pubkey: ScriptBuf::new_p2sh(&ScriptHash::from_byte_array(DUMMY20)),
        };
        let p2pkh_txout = TxOut {
            value: Amount::from_sat(456),
            script_pubkey: ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(DUMMY20)),
        };
        let utxo = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: LockTime::Seconds(Time::MIN),
            input: vec![],
            output: vec![p2sh_txout, p2pkh_txout],
        };
        let outpoint = OutPoint { txid: utxo.compute_txid(), vout: 0 };
        let sequence = Sequence::from_512_second_intervals(123);
        let redeem_script = ScriptBuf::new_p2sh(&ScriptHash::from_byte_array(DUMMY20));

        let p2sh_pair =
            InputPair::new_p2sh(utxo.clone(), outpoint, redeem_script.clone(), Some(sequence));

        assert_eq!(
            p2sh_pair.err().unwrap(),
            PsbtInputError::from(InternalPsbtInputError::from(InputWeightError::NotSupported))
        );

        // Failures
        let utxo_with_p2pkh = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: LockTime::Seconds(Time::MIN),
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(123),
                script_pubkey: ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(DUMMY20)),
            }],
        };
        let outpoint = OutPoint { txid: utxo_with_p2pkh.compute_txid(), vout: 0 };
        let redeem_script = ScriptBuf::new_p2sh(&ScriptHash::from_byte_array(DUMMY20));
        let invalid_p2sh_pair =
            InputPair::new_p2sh(utxo_with_p2pkh.clone(), outpoint, redeem_script.clone(), None);
        assert_eq!(
            invalid_p2sh_pair.err().unwrap(),
            PsbtInputError::from(InvalidScriptPubKey(AddressType::P2sh))
        );

        let utxo_empty_outputs = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: LockTime::Seconds(Time::MIN),
            input: vec![],
            output: vec![],
        };
        let outpoint = OutPoint { txid: utxo_empty_outputs.compute_txid(), vout: 0 };
        let invalid_p2sh_pair =
            InputPair::new_p2sh(utxo_empty_outputs.clone(), outpoint, redeem_script, None);
        assert_eq!(
            invalid_p2sh_pair.err().unwrap(),
            PsbtInputError::from(InternalPsbtInputError::PrevTxOut(
                PrevTxOutError::IndexOutOfBounds { index: outpoint.vout, output_count: 0 }
            ))
        );
    }

    #[test]
    fn create_p2wpkh_input_pair() {
        let outpoint = OutPoint { txid: Txid::from_byte_array(DUMMY32), vout: 31 };
        let sequence = Sequence::from_512_second_intervals(123);
        let p2wpkh_txout = TxOut {
            value: Amount::from_sat(12345),
            script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(DUMMY20)),
        };
        let p2wpkh_pair =
            InputPair::new_p2wpkh(p2wpkh_txout.clone(), outpoint, Some(sequence)).unwrap();
        assert_eq!(p2wpkh_pair.txin.previous_output, outpoint);
        assert_eq!(p2wpkh_pair.txin.sequence, sequence);
        assert_eq!(p2wpkh_pair.psbtin.witness_utxo.unwrap(), p2wpkh_txout);
        assert_eq!(
            p2wpkh_pair.expected_weight,
            InputWeightPrediction::P2WPKH_MAX.weight() + NON_WITNESS_DATA_WEIGHT
        );

        let p2sh_txout = TxOut {
            value: Default::default(),
            script_pubkey: ScriptBuf::new_p2sh(&ScriptHash::all_zeros()),
        };
        assert_eq!(
            InputPair::new_p2wpkh(p2sh_txout, outpoint, Some(sequence)).err().unwrap(),
            PsbtInputError::from(InvalidScriptPubKey(AddressType::P2wpkh))
        )
    }

    #[test]
    fn create_p2wsh_input_pair() {
        let outpoint = OutPoint { txid: Txid::from_byte_array(DUMMY32), vout: 31 };
        let sequence = Sequence::from_512_second_intervals(123);
        let p2wsh_txout = TxOut {
            value: Amount::from_sat(12345),
            script_pubkey: ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array(DUMMY32)),
        };
        let expected_weight = Weight::from_wu(42);
        let p2wsh_pair =
            InputPair::new_p2wsh(p2wsh_txout.clone(), outpoint, Some(sequence), expected_weight)
                .expect("valid params for p2wsh");

        assert_eq!(p2wsh_pair.txin.previous_output, outpoint);
        assert_eq!(p2wsh_pair.txin.sequence, sequence);
        assert_eq!(p2wsh_pair.psbtin.witness_utxo.unwrap(), p2wsh_txout);
        assert_eq!(p2wsh_pair.expected_weight, expected_weight);

        let p2wsh_pair = InputPair::new(
            TxIn { previous_output: outpoint, sequence, ..Default::default() },
            psbt::Input { witness_utxo: Some(p2wsh_txout.clone()), ..Default::default() },
            None,
        );
        // P2wsh is not supported when expected weight is not provided
        assert_eq!(
            p2wsh_pair.err().unwrap(),
            PsbtInputError::from(InternalPsbtInputError::from(InputWeightError::NotSupported))
        );

        let p2sh_txout = TxOut {
            value: Default::default(),
            script_pubkey: ScriptBuf::new_p2sh(&ScriptHash::all_zeros()),
        };
        assert_eq!(
            InputPair::new_p2wsh(p2sh_txout, outpoint, Some(sequence), expected_weight)
                .err()
                .unwrap(),
            PsbtInputError::from(InvalidScriptPubKey(AddressType::P2wsh))
        );

        let mut dummy_witness = witness::Witness::new();
        dummy_witness.push(DUMMY32);
        let txin = TxIn {
            previous_output: outpoint,
            witness: dummy_witness.clone(),
            ..Default::default()
        };
        let input_weight = Weight::from_non_witness_data_size(txin.base_size() as u64)
            + Weight::from_witness_data_size(dummy_witness.size() as u64);

        // Add the witness straight to the txin
        let psbtin = psbt::Input { witness_utxo: Some(p2wsh_txout.clone()), ..Default::default() };
        let p2wsh_pair = InputPair::new(txin, psbtin, None).expect("witness is provided for p2wsh");
        assert_eq!(p2wsh_pair.expected_weight, input_weight);
        // Same check but add the witness to the psbtin
        let txin = TxIn { previous_output: outpoint, ..Default::default() };
        let psbtin = psbt::Input {
            witness_utxo: Some(p2wsh_txout),
            final_script_witness: Some(dummy_witness),
            ..Default::default()
        };
        let p2wsh_pair = InputPair::new(txin.clone(), psbtin.clone(), None)
            .expect("witness is provided for p2wsh");
        assert_eq!(p2wsh_pair.expected_weight, input_weight);

        // Should error out if expected weight is provided and witness is provided
        let p2wsh_pair = InputPair::new(txin, psbtin, Some(expected_weight));
        assert_eq!(
            p2wsh_pair.err().unwrap(),
            PsbtInputError::from(InternalPsbtInputError::ProvidedUnnecessaryWeight)
        );
    }

    #[test]
    fn create_p2tr_input_pair() {
        let outpoint = OutPoint { txid: Txid::from_byte_array(DUMMY32), vout: 31 };
        let sequence = Sequence::from_512_second_intervals(123);
        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = pubkey_string.parse::<PublicKey>().expect("valid pubkey");
        let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);
        let p2tr_txout = TxOut {
            value: Amount::from_sat(12345),
            script_pubkey: ScriptBuf::new_p2tr(&Secp256k1::new(), xonly_pubkey, None),
        };
        let p2tr_pair = InputPair::new_p2tr(p2tr_txout.clone(), outpoint, Some(sequence)).unwrap();
        assert_eq!(p2tr_pair.txin.previous_output, outpoint);
        assert_eq!(p2tr_pair.txin.sequence, sequence);
        assert_eq!(p2tr_pair.psbtin.witness_utxo.unwrap(), p2tr_txout);
        assert_eq!(
            p2tr_pair.expected_weight,
            InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH.weight() + NON_WITNESS_DATA_WEIGHT
        );

        let p2sh_txout = TxOut {
            value: Default::default(),
            script_pubkey: ScriptBuf::new_p2sh(&ScriptHash::all_zeros()),
        };
        assert_eq!(
            InputPair::new_p2tr(p2sh_txout, outpoint, Some(sequence)).err().unwrap(),
            PsbtInputError::from(InvalidScriptPubKey(AddressType::P2tr))
        )
    }

    #[test]
    fn test_interleave_shuffle() {
        let mut original1 = vec![1, 2, 3];
        let mut original2 = original1.clone();
        let mut original3 = original1.clone();
        let mut new1 = vec![4, 5, 6];
        let mut new2 = new1.clone();
        let mut new3 = new1.clone();
        let mut rng1 = StdRng::seed_from_u64(123);
        let mut rng2 = StdRng::seed_from_u64(234);
        let mut rng3 = StdRng::seed_from_u64(345);
        // Operate on the same data multiple times with different RNG seeds.
        interleave_shuffle(&mut original1, &mut new1, &mut rng1);
        interleave_shuffle(&mut original2, &mut new2, &mut rng2);
        interleave_shuffle(&mut original3, &mut new3, &mut rng3);
        // The result should be different for each seed
        // and the relative ordering from `original` always preserved/
        assert_eq!(original1, vec![1, 6, 2, 5, 4, 3]);
        assert_eq!(original2, vec![1, 5, 4, 2, 6, 3]);
        assert_eq!(original3, vec![4, 5, 1, 2, 6, 3]);
    }
}
