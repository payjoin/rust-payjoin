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

use bitcoin::hashes::sha256d;
use bitcoin::transaction::InputWeightPrediction;
use bitcoin::{
    psbt, AddressType, FeeRate, OutPoint, Psbt, Script, ScriptBuf, Transaction, TxIn, TxOut, Weight,
};
pub(crate) use error::InternalPayloadError;
pub use error::{
    Error, InputContributionError, JsonReply, OutputSubstitutionError, PayloadError, ProtocolError,
    SelectionError,
};
use optional_parameters::Params;
use serde::{Deserialize, Serialize};

pub use crate::psbt::PsbtInputError;
use crate::psbt::{
    InputWeightError, InternalInputPair, InternalPsbtInputError, PrevTxOutError, PsbtExt,
    NON_WITNESS_INPUT_WEIGHT,
};
use crate::{ImplementationError, Version};

/// Input weight for a P2TR key-spend with default sighash (64-byte signature) and no annex.
const DEFAULT_SIGHASH_KEY_SPEND_INPUT_WEIGHT: Weight = Weight::from_wu(
    InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH.weight().to_wu()
        + NON_WITNESS_INPUT_WEIGHT.to_wu(),
);

pub(crate) mod common;
mod error;
pub(crate) mod optional_parameters;

#[cfg(feature = "v1")]
#[cfg_attr(docsrs, doc(cfg(feature = "v1")))]
pub mod v1;

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
        redeem_script: Option<ScriptBuf>,
    ) -> Result<Self, PsbtInputError> {
        let txin = TxIn {
            previous_output: OutPoint { txid: outpoint.txid, vout: outpoint.vout },
            ..Default::default()
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
    ) -> Result<Self, PsbtInputError> {
        let txout = Self::get_txout_for_outpoint(&non_witness_utxo, outpoint)?;
        if !txout.script_pubkey.is_p2pkh() {
            return Err(InternalPsbtInputError::InvalidScriptPubKey(AddressType::P2pkh).into());
        }
        Self::new_legacy_input_pair(non_witness_utxo, outpoint, None)
    }

    /// Constructs a new [`InputPair`] for spending a legacy P2SH output.
    pub fn new_p2sh(
        non_witness_utxo: Transaction,
        outpoint: OutPoint,
        redeem_script: ScriptBuf,
    ) -> Result<Self, PsbtInputError> {
        let txout = Self::get_txout_for_outpoint(&non_witness_utxo, outpoint)?;
        if !txout.script_pubkey.is_p2sh() {
            return Err(InternalPsbtInputError::InvalidScriptPubKey(AddressType::P2sh).into());
        }
        Self::new_legacy_input_pair(non_witness_utxo, outpoint, Some(redeem_script))
    }

    /// Helper function for creating SegWit input pairs
    fn new_segwit_input_pair(
        txout: TxOut,
        outpoint: OutPoint,
        expected_weight: Option<Weight>,
    ) -> Result<Self, PsbtInputError> {
        let txin = TxIn {
            previous_output: OutPoint { txid: outpoint.txid, vout: outpoint.vout },
            ..Default::default()
        };

        let psbtin = psbt::Input {
            witness_utxo: Some(TxOut { value: txout.value, script_pubkey: txout.script_pubkey }),
            ..psbt::Input::default()
        };

        Self::new(txin, psbtin, expected_weight)
    }

    /// Constructs a new [`InputPair`] for spending a native SegWit P2WPKH output.
    pub fn new_p2wpkh(txout: TxOut, outpoint: OutPoint) -> Result<Self, PsbtInputError> {
        if !txout.script_pubkey.is_p2wpkh() {
            return Err(InternalPsbtInputError::InvalidScriptPubKey(AddressType::P2wpkh).into());
        }

        Self::new_segwit_input_pair(txout, outpoint, None)
    }

    /// Constructs a new [`InputPair`] for spending a native SegWit P2WSH output.
    pub fn new_p2wsh(
        txout: TxOut,
        outpoint: OutPoint,
        expected_weight: Weight,
    ) -> Result<Self, PsbtInputError> {
        if !txout.script_pubkey.is_p2wsh() {
            return Err(InternalPsbtInputError::InvalidScriptPubKey(AddressType::P2wsh).into());
        }

        Self::new_segwit_input_pair(txout, outpoint, Some(expected_weight))
    }

    /// Constructs a new [`InputPair`] for spending a native SegWit P2TR output
    /// via the key spend path using the default taproot sighash (64-byte
    /// signature) and no annex.
    pub fn new_p2tr_keyspend(txout: TxOut, outpoint: OutPoint) -> Result<Self, PsbtInputError> {
        if !txout.script_pubkey.is_p2tr() {
            return Err(InternalPsbtInputError::InvalidScriptPubKey(AddressType::P2tr).into());
        }

        Self::new_segwit_input_pair(txout, outpoint, Some(DEFAULT_SIGHASH_KEY_SPEND_INPUT_WEIGHT))
    }

    /// Constructs a new [`InputPair`] for spending a native SegWit P2TR output via the script path.
    /// Callers must provide the expected input satisfiability weight. Ensure `expected_weight`
    /// accurately reflects your script-path spend. Incorrect weight may cause fee calculation errors.
    /// Use [`new_p2tr_keyspend`](Self::new_p2tr_keyspend) for key-path spends.
    pub fn new_p2tr_scriptpath_spend(
        txout: TxOut,
        outpoint: OutPoint,
        expected_weight: Weight,
    ) -> Result<Self, PsbtInputError> {
        if !txout.script_pubkey.is_p2tr() {
            return Err(InternalPsbtInputError::InvalidScriptPubKey(AddressType::P2tr).into());
        }

        Self::new_segwit_input_pair(txout, outpoint, Some(expected_weight))
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

/// Tag used within [`TaggedValidatorReference`] to store a validation result
///
/// The particular implementation of this trait used is what defines the type of validation
/// [`FinalizedValidator`] is for.
pub trait ValidatorReferenceTag {
    /// Create a new tag that contains validation result
    fn new(tag: bool) -> Self;

    /// Return whether tag is true within
    fn is_true(&self) -> bool;
}

pub struct InputOwnedTag(bool);
impl ValidatorReferenceTag for InputOwnedTag {
    fn new(tag: bool) -> Self { InputOwnedTag(tag) }
    fn is_true(&self) -> bool { self.0 }
}

pub struct InputSeenTag(bool);
impl ValidatorReferenceTag for InputSeenTag {
    fn new(tag: bool) -> Self { InputSeenTag(tag) }
    fn is_true(&self) -> bool { self.0 }
}

pub struct OutputOwnedTag(bool);
impl ValidatorReferenceTag for OutputOwnedTag {
    fn new(tag: bool) -> Self { OutputOwnedTag(tag) }
    fn is_true(&self) -> bool { self.0 }
}

/// Holds the value to be validated by validator
pub struct ValidatorReference<R>
where
    R: Clone,
{
    value: R,
    index: usize,
}

impl<R> ValidatorReference<R>
where
    R: Clone,
{
    pub(crate) fn get_value(&self) -> R { self.value.clone() }
    pub(crate) fn get_index(&self) -> usize { self.index }

    /// Mark the ValidatorReference with a tag
    pub(crate) fn mark<T>(self, tag: T) -> TaggedValidatorReference<R, T>
    where
        T: ValidatorReferenceTag,
    {
        TaggedValidatorReference { reference: self, tag }
    }
}

/// Holds the tagged value to be returned to the validator
pub struct TaggedValidatorReference<R, T>
where
    R: Clone,
    T: ValidatorReferenceTag,
{
    reference: ValidatorReference<R>,
    tag: T,
}

impl<R, T> TaggedValidatorReference<R, T>
where
    R: Clone,
    T: ValidatorReferenceTag,
{
    /// Return whether TaggedValidatorReference's tag is true within
    pub(crate) fn is_true(&self) -> bool { self.tag.is_true() }
}

/// Used to apply validation over a list of items.
///
/// [`Validator::run`] and [`Validator::run_async`] take a validation callback,
/// run it over the Iterator of items to be validated, and return a
/// [`FinalizedValidator`] that holds the result of each item.
struct Validator<I, R>(I, sha256d::Hash)
where
    I: Iterator<Item = ValidatorReference<R>>,
    R: Clone;

impl<I, R> Validator<I, R>
where
    I: Iterator<Item = ValidatorReference<R>>,
    R: Clone,
{
    fn new(values: I, identifier: sha256d::Hash) -> Validator<I, R> {
        Validator(values, identifier)
    }
    /// Takes a synchronous validation callback, applies the validation callback over its wrapped
    /// Iterator of [`ValidatorReference`]s, and returns a [`FinalizedValidator`] that
    /// holds the result of each item.
    pub fn run<T>(
        self,
        validation_callback: &mut impl FnMut(&R) -> Result<bool, ImplementationError>,
    ) -> Result<
        FinalizedValidator<impl IntoIterator<Item = TaggedValidatorReference<R, T>>, R, T>,
        ImplementationError,
    >
    where
        T: ValidatorReferenceTag,
    {
        let mut tagged_refs: Vec<TaggedValidatorReference<R, T>> = vec![];
        for reference in self.0 {
            let tag = T::new(validation_callback(&reference.get_value())?);
            let tagged_ref = reference.mark(tag);
            tagged_refs.push(tagged_ref);
        }
        Ok(FinalizedValidator(tagged_refs, self.1))
    }

    /// Takes an asynchronous validation callback, applies the validation callback over its
    /// wrapped Iterator of [`ValidatorReference`]s, and returns a [`FinalizedValidator`]
    /// that holds the result of each item.
    pub async fn run_async<F, Fut, T>(
        self,
        mut validation_callback: F,
    ) -> Result<
        FinalizedValidator<impl IntoIterator<Item = TaggedValidatorReference<R, T>>, R, T>,
        ImplementationError,
    >
    where
        F: FnMut(&R) -> Fut,
        Fut: std::future::Future<Output = Result<bool, ImplementationError>>,
        T: ValidatorReferenceTag,
    {
        let mut tagged_refs: Vec<TaggedValidatorReference<R, T>> = vec![];
        for reference in self.0 {
            let tag = T::new(validation_callback(&reference.get_value()).await?);
            let tagged_ref = reference.mark(tag);
            tagged_refs.push(tagged_ref);
        }
        Ok(FinalizedValidator(tagged_refs, self.1))
    }
}

/// Runs validation for checking which inputs are owned on original PSBT
///
/// [`InputsOwnedValidator::run`] takes a validation callback, applies it
/// over each item in the wrapped Iterator, and returns a
/// [`FinalizedValidator`] that holds the result
/// of each item. This is [`InputsOwnedValidator`]'s only purpose.
pub struct InputsOwnedValidator<I>(Validator<I, ScriptBuf>)
where
    I: Iterator<Item = ValidatorReference<ScriptBuf>>;

impl InputsOwnedValidator<std::iter::Empty<ValidatorReference<ScriptBuf>>> {
    pub fn new(
        psbt: &Psbt,
    ) -> Result<InputsOwnedValidator<impl Iterator<Item = ValidatorReference<ScriptBuf>>>, Error>
    {
        let input_script_refs: Result<Vec<ValidatorReference<ScriptBuf>>, Error> = psbt
            .input_pairs()
            .enumerate()
            .map(|(index, input)| match input.previous_txout() {
                Ok(txout) =>
                    Ok(ValidatorReference { index, value: txout.script_pubkey.to_owned() }),
                Err(e) => Err(InternalPayloadError::PrevTxOut(e).into()),
            })
            .collect();
        Ok(InputsOwnedValidator(Validator(
            input_script_refs?.into_iter(),
            psbt.unsigned_tx.compute_ntxid(),
        )))
    }
}

impl<I> InputsOwnedValidator<I>
where
    I: Iterator<Item = ValidatorReference<ScriptBuf>>,
{
    /// Takes a synchronous validation callback, applies the validation callback over its wrapped
    /// Iterator of [`ValidatorReference`]s, and returns a [`FinalizedValidator`] that
    /// holds the result of each item.
    pub fn run(
        self,
        validation_callback: &mut impl FnMut(&ScriptBuf) -> Result<bool, ImplementationError>,
    ) -> Result<
        FinalizedValidator<
            impl IntoIterator<Item = TaggedValidatorReference<ScriptBuf, InputOwnedTag>>,
            ScriptBuf,
            InputOwnedTag,
        >,
        ImplementationError,
    > {
        self.0.run(validation_callback)
    }

    /// Takes an asynchronous validation callback, applies the validation callback over its
    /// wrapped Iterator of [`ValidatorReference`]s, and returns a [`FinalizedValidator`]
    /// that holds the result of each item.
    pub async fn run_async<F, Fut>(
        self,
        validation_callback: F,
    ) -> Result<
        FinalizedValidator<
            impl IntoIterator<Item = TaggedValidatorReference<ScriptBuf, InputOwnedTag>>,
            ScriptBuf,
            InputOwnedTag,
        >,
        ImplementationError,
    >
    where
        F: FnMut(&ScriptBuf) -> Fut,
        Fut: std::future::Future<Output = Result<bool, ImplementationError>>,
    {
        self.0.run_async(validation_callback).await
    }
}

/// Runs validation for checking which inputs have been seen on original PSBT
///
/// [`InputsSeenValidator::run`] takes a validation callback, applies it
/// over each item in the wrapped Iterator, and returns a
/// [`FinalizedValidator`] that holds the result
/// of each item. This is [`InputsSeenValidator`]'s only purpose.
pub struct InputsSeenValidator<I>(Validator<I, OutPoint>)
where
    I: Iterator<Item = ValidatorReference<OutPoint>>;

impl InputsSeenValidator<std::iter::Empty<ValidatorReference<OutPoint>>> {
    pub(crate) fn new(
        psbt: &Psbt,
    ) -> InputsSeenValidator<impl Iterator<Item = ValidatorReference<OutPoint>>> {
        let input_outpoint_refs: Vec<ValidatorReference<OutPoint>> = psbt
            .input_pairs()
            .enumerate()
            .map(|(index, input)| ValidatorReference { index, value: input.txin.previous_output })
            .collect();
        InputsSeenValidator(Validator::new(
            input_outpoint_refs.into_iter(),
            psbt.unsigned_tx.compute_ntxid(),
        ))
    }
}

impl<I> InputsSeenValidator<I>
where
    I: Iterator<Item = ValidatorReference<OutPoint>>,
{
    /// Takes a synchronous validation callback, applies the validation callback over its wrapped
    /// Iterator of [`ValidatorReference`]s, and returns a [`FinalizedValidator`] that
    /// holds the result of each item.
    pub fn run(
        self,
        validation_callback: &mut impl FnMut(&OutPoint) -> Result<bool, ImplementationError>,
    ) -> Result<
        FinalizedValidator<
            impl IntoIterator<Item = TaggedValidatorReference<OutPoint, InputSeenTag>>,
            OutPoint,
            InputSeenTag,
        >,
        ImplementationError,
    > {
        self.0.run(validation_callback)
    }

    /// Takes an asynchronous validation callback, applies the validation callback over its
    /// wrapped Iterator of [`ValidatorReference`]s, and returns a [`FinalizedValidator`]
    /// that holds the result of each item.
    pub async fn run_async<F, Fut>(
        self,
        validation_callback: F,
    ) -> Result<
        FinalizedValidator<
            impl IntoIterator<Item = TaggedValidatorReference<OutPoint, InputSeenTag>>,
            OutPoint,
            InputSeenTag,
        >,
        ImplementationError,
    >
    where
        F: FnMut(&OutPoint) -> Fut,
        Fut: std::future::Future<Output = Result<bool, ImplementationError>>,
    {
        self.0.run_async(validation_callback).await
    }
}

/// Runs validation for checking which outputs are owned on original PSBT
///
/// [`OutputsOwnedValidator::run`] takes a validation callback, applies it
/// over each item in the wrapped Iterator, and returns a
/// [`FinalizedValidator`] that holds the result
/// of each item. This is [`OutputsOwnedValidator`]'s only purpose.
pub struct OutputsOwnedValidator<I>(Validator<I, ScriptBuf>)
where
    I: Iterator<Item = ValidatorReference<ScriptBuf>>;

impl OutputsOwnedValidator<std::iter::Empty<ValidatorReference<ScriptBuf>>> {
    fn new(
        psbt: &Psbt,
    ) -> OutputsOwnedValidator<impl Iterator<Item = ValidatorReference<ScriptBuf>>> {
        let output_script_refs: Vec<ValidatorReference<ScriptBuf>> = psbt
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .map(|(index, output)| ValidatorReference {
                index,
                value: output.script_pubkey.to_owned(),
            })
            .collect();
        OutputsOwnedValidator(Validator::new(
            output_script_refs.into_iter(),
            psbt.unsigned_tx.compute_ntxid(),
        ))
    }
}

impl<I> OutputsOwnedValidator<I>
where
    I: Iterator<Item = ValidatorReference<ScriptBuf>>,
{
    /// Takes a synchronous validation callback, applies the validation callback over its wrapped
    /// Iterator of [`ValidatorReference`]s, and returns a [`FinalizedValidator`] that
    /// holds the result of each item.
    pub fn run(
        self,
        validation_callback: &mut impl FnMut(&ScriptBuf) -> Result<bool, ImplementationError>,
    ) -> Result<
        FinalizedValidator<
            impl IntoIterator<Item = TaggedValidatorReference<ScriptBuf, OutputOwnedTag>>,
            ScriptBuf,
            OutputOwnedTag,
        >,
        ImplementationError,
    > {
        self.0.run(validation_callback)
    }

    /// Takes an asynchronous validation callback, applies the validation callback over its
    /// wrapped Iterator of [`ValidatorReference`]s, and returns a [`FinalizedValidator`]
    /// that holds the result of each item.
    pub async fn run_async<F, Fut>(
        self,
        validation_callback: F,
    ) -> Result<
        FinalizedValidator<
            impl IntoIterator<Item = TaggedValidatorReference<ScriptBuf, OutputOwnedTag>>,
            ScriptBuf,
            OutputOwnedTag,
        >,
        ImplementationError,
    >
    where
        F: FnMut(&ScriptBuf) -> Fut,
        Fut: std::future::Future<Output = Result<bool, ImplementationError>>,
    {
        self.0.run_async(validation_callback).await
    }
}

/// Used to return validation results for a list of items
///
/// The only ways to create a [`FinalizedValidator`] is by calling `run` or
/// `run_async` on [`InputsOwnedValidator`], [`InputsSeenValidator`] or
/// [`OutputsOwnedValidator`]
pub struct FinalizedValidator<I, R, T>(I, sha256d::Hash)
where
    I: IntoIterator<Item = TaggedValidatorReference<R, T>>,
    R: Clone,
    T: ValidatorReferenceTag;

impl<I, R, T> FinalizedValidator<I, R, T>
where
    I: IntoIterator<Item = TaggedValidatorReference<R, T>>,
    R: Clone,
    T: ValidatorReferenceTag,
{
    /// Takes an expected count and expected ntxid and verifies the [`FinalizedValidator`]
    /// has all indexes accounted for, matches the expected count, matches the expected
    /// ntxid, and returns an Iterator of [`ValidatorReference`]s that have a positive
    /// result.
    pub(crate) fn verify(
        self,
        expected_count: usize,
        expected_ntxid: sha256d::Hash,
    ) -> Result<impl Iterator<Item = ValidatorReference<R>>, ImplementationError> {
        if expected_ntxid != self.1 {
            return Err(ImplementationError::from(
                "Validation error: encountered unexpected identifier",
            ));
        }
        let refs = self.0.into_iter();
        let mut running_index: usize = 0;
        let positives_result: Result<Vec<_>, ImplementationError> = refs
            .enumerate()
            .filter_map(|(index, tagged_ref)| {
                running_index = index;
                if index != tagged_ref.reference.get_index() {
                    return Some(Err(ImplementationError::from(
                        "Validation error: encountered unexpected reference index",
                    )));
                };
                match tagged_ref.is_true() {
                    true => Some(Ok(tagged_ref.reference)),
                    false => None,
                }
            })
            .collect();
        if expected_count != running_index + 1 {
            return Err(ImplementationError::from(
                "Validation error: encountered unexpected number of references",
            ));
        }
        Ok(positives_result?.into_iter())
    }
}

/// Validate the payload of a Payjoin request for PSBT and Params sanity
pub(crate) fn parse_payload(
    base64: &str,
    query: &str,
    supported_versions: &'static [Version],
) -> Result<(Psbt, Params), PayloadError> {
    let unchecked_psbt = Psbt::from_str(base64).map_err(InternalPayloadError::ParsePsbt)?;

    let psbt = unchecked_psbt.validate().map_err(InternalPayloadError::InconsistentPsbt)?;
    tracing::trace!("Received original psbt: {psbt:?}");

    let params = Params::from_query_str(query, supported_versions)
        .map_err(InternalPayloadError::SenderParams)?;
    tracing::trace!("Received request with params: {params:?}");

    Ok((psbt, params))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PsbtContext {
    original_psbt: Psbt,
    payjoin_psbt: Psbt,
}

impl PsbtContext {
    /// Prepare the PSBT by creating a new PSBT and copying only the fields allowed by the [spec](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#senders-payjoin-proposal-checklist)
    fn prepare_psbt(self, processed_psbt: &Psbt) -> Psbt {
        tracing::trace!("Original PSBT from callback: {processed_psbt:#?}");

        // Create a new PSBT and copy only the allowed fields
        let mut filtered_psbt = Psbt {
            unsigned_tx: processed_psbt.unsigned_tx.clone(),
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

        tracing::trace!("Filtered PSBT: {filtered_psbt:#?}");

        filtered_psbt
    }

    /// Return the indexes of the sender inputs.
    fn sender_input_indexes(&self) -> Vec<usize> {
        // iterate proposal as mutable WITH the outpoint (previous_output) available too
        let mut original_inputs = self.original_psbt.input_pairs().peekable();
        let mut sender_input_indexes = vec![];
        for (i, input) in self.payjoin_psbt.input_pairs().enumerate() {
            if let Some(original) = original_inputs.peek() {
                tracing::trace!(
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

    /// Return the payjoin PSBT that is ready for signing
    fn payjoin_psbt_without_sender_signatures(&self) -> Psbt {
        let mut psbt = self.payjoin_psbt.clone();
        // Remove now-invalid sender signatures before applying the receiver signatures
        for i in self.sender_input_indexes() {
            psbt.inputs[i].final_script_sig = None;
            psbt.inputs[i].final_script_witness = None;
            psbt.inputs[i].tap_key_sig = None;
        }
        psbt
    }

    /// Finalizes the Payjoin proposal into a PSBT which the sender will find acceptable before
    /// they sign the transaction and broadcast it to the network.
    ///
    /// Finalization consists of two steps:
    ///   1. Validate that signed psbt contains expected inputs and outputs
    ///   2. Prepare the psbt to be sent to sender
    fn finalize_proposal(self, signed_psbt: &Psbt) -> Result<Psbt, ImplementationError> {
        let expected_ntxid = self.payjoin_psbt.unsigned_tx.compute_ntxid();
        let actual_ntxid = signed_psbt.unsigned_tx.compute_ntxid();
        if expected_ntxid != actual_ntxid {
            return Err(ImplementationError::from(
                format!("Ntxid mismatch: expected {expected_ntxid}, got {actual_ntxid}").as_str(),
            ));
        }
        let payjoin_proposal = self.prepare_psbt(signed_psbt);
        Ok(payjoin_proposal)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OriginalPayload {
    psbt: Psbt,
    params: Params,
}

impl OriginalPayload {
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
    ) -> Result<(), Error> {
        self.process_broadcast_suitability_result(
            min_fee_rate,
            can_broadcast(&self.psbt.clone().extract_tx_unchecked_fee_rate())?,
        )
    }

    pub fn process_broadcast_suitability_result(
        &self,
        min_fee_rate: Option<FeeRate>,
        can_broadcast: bool,
    ) -> Result<(), Error> {
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
        if can_broadcast {
            Ok(())
        } else {
            Err(InternalPayloadError::OriginalPsbtNotBroadcastable.into())
        }
    }

    /// Check that the original PSBT has no receiver owned inputs.
    ///
    /// An attacker can try to spend the receiver's own inputs. This check prevents that.
    pub fn check_inputs_not_owned(
        &self,
        is_owned: &mut impl FnMut(&Script) -> Result<bool, ImplementationError>,
    ) -> Result<(), Error> {
        let validator = InputsOwnedValidator::new(&self.psbt)?;
        let finalized_validator =
            validator.run(&mut |script_buf| is_owned(script_buf.as_script()))?;
        self.process_inputs_owned_validator(finalized_validator)
    }

    /// Get a [`InputsOwnedValidator`] for checking original PSBT has no receiver owend inputs.
    ///
    /// An attacker can try to spend the receiver's own inputs. This check prevents that.
    ///
    /// Returns a [`InputsOwnedValidator`] for checking whether the inputs are receiver owned.
    /// Run the [`InputsOwnedValidator`] using [`InputsOwnedValidator::run`] or
    /// [`InputsOwnedValidator::run_async`] and submit the resulting [`FinalizedValidator`] to
    /// [`OriginalPayload::process_inputs_owned_validator`].
    pub fn get_inputs_owned_validator(
        &self,
    ) -> Result<InputsOwnedValidator<impl Iterator<Item = ValidatorReference<ScriptBuf>>>, Error>
    {
        InputsOwnedValidator::new(&self.psbt)
    }

    /// Processes a [`FinalizedValidator`] by verifying it and ensuring original PSBT has no
    /// receiver owned inputs.
    ///
    /// An attacker can try to spend the receiver's own inputs. This check prevents that.
    ///
    /// Takes a [`FinalizedValidator`], verifies it is valid for the original PSBT, and checks
    /// that none of the inputs tested positive for being receiver owned. Use
    /// [`InputsOwnedValidator::run`]
    /// or [`InputsOwnedValidator::run_async`] to get a [`FinalizedValidator`].
    pub fn process_inputs_owned_validator(
        &self,
        finalized_validator: FinalizedValidator<
            impl IntoIterator<Item = TaggedValidatorReference<ScriptBuf, InputOwnedTag>>,
            ScriptBuf,
            InputOwnedTag,
        >,
    ) -> Result<(), Error> {
        let mut owned_input_scripts = finalized_validator
            .verify(self.psbt.inputs.len(), self.psbt.unsigned_tx.compute_ntxid())?
            .map(|tagged_ref| tagged_ref.get_value());
        match owned_input_scripts.next() {
            Some(input_script) => Err(InternalPayloadError::InputOwned(input_script).into()),
            None => Ok(()),
        }
    }

    /// Check that the original PSBT has no receiver seen inputs.
    ///
    /// An attacker can try to dox the receivers addresses by sending the same original
    /// PSBT multiple times. This check prevents that.
    pub fn check_no_inputs_seen_before(
        &self,
        is_known: &mut impl FnMut(&OutPoint) -> Result<bool, ImplementationError>,
    ) -> Result<(), Error> {
        let validator = InputsSeenValidator::new(&self.psbt);
        let finalized_validator = validator.run(is_known)?;
        self.process_inputs_seen_validator(finalized_validator)
    }

    /// Get a [`InputsSeenValidator`] for checking original PSBT has no receiver seen inputs.
    ///
    /// An attacker can try to dox the receivers addresses by sending the same original
    /// PSBT multiple times. This check prevents that.
    ///
    /// Returns a [`InputsSeenValidator`] for checking whether the inputs have been seen by the receiver.
    /// Run the [`InputsSeenValidator`] using [`InputsSeenValidator::run`] or
    /// [`InputsSeenValidator::run_async`] and submit the resulting [`FinalizedValidator`] to
    /// [`OriginalPayload::process_inputs_seen_validator`].
    pub fn get_inputs_seen_validator(
        &self,
    ) -> InputsSeenValidator<impl Iterator<Item = ValidatorReference<OutPoint>>> {
        InputsSeenValidator::new(&self.psbt)
    }

    /// Processes a [`FinalizedValidator`] by verifying it and ensuring original PSBT has no
    /// receiver seen inputs.
    ///
    /// An attacker can try to dox the receivers addresses by sending the same original
    /// PSBT multiple times. This check prevents that.
    ///
    /// Takes a [`FinalizedValidator`], verifies it is valid for the original PSBT, and checks
    /// that none of the inputs tested positive for being seen by the receiver. Get a
    /// [`InputsSeenValidator`]
    /// from [`OriginalPayload::get_inputs_seen_validator`] and use [`InputsSeenValidator::run`]
    /// or [`InputsSeenValidator::run_async`] to get a [`FinalizedValidator`].
    pub fn process_inputs_seen_validator(
        &self,
        finalized_validator: FinalizedValidator<
            impl IntoIterator<Item = TaggedValidatorReference<OutPoint, InputSeenTag>>,
            OutPoint,
            InputSeenTag,
        >,
    ) -> Result<(), Error> {
        let mut seen_input_outpoints = finalized_validator
            .verify(self.psbt.inputs.len(), self.psbt.unsigned_tx.compute_ntxid())?
            .map(|tagged_ref| tagged_ref.get_value());
        match seen_input_outpoints.next() {
            Some(input_outpoint) => {
                tracing::warn!("Request contains an input we've seen before: {}. Preventing possible probing attack.", input_outpoint);
                Err(InternalPayloadError::InputSeen(input_outpoint))?
            }
            None => Ok(()),
        }
    }

    /// Check that the original PSBT has receiver owned outputs.
    ///
    /// An attacker can try to steal funds from the receiver inputs added to the payjoin
    /// by not including any receiver owned outputs. This check prevents that.
    pub fn identify_receiver_outputs(
        &self,
        is_receiver_output: &mut impl FnMut(&Script) -> Result<bool, ImplementationError>,
    ) -> Result<common::WantsOutputs, Error> {
        let validator = OutputsOwnedValidator::new(&self.psbt);
        let finalized_validator =
            validator.run(&mut |script_buf| is_receiver_output(script_buf.as_script()))?;
        self.process_outputs_owned_validator(finalized_validator)
    }

    /// Get a [`OutputsOwnedValidator`] for checking original PSBT has receiver owned outputs.
    ///
    /// An attacker can try to steal funds from the receiver inputs added to the payjoin
    /// by not including any receiver owned outputs. This check prevents that.
    ///
    /// Returns a [`OutputsOwnedValidator`] for checking whether the receiver owns any of the outputs.
    /// Run the [`OutputsOwnedValidator`] using [`OutputsOwnedValidator::run`] or
    /// [`OutputsOwnedValidator::run_async`] and submit the resulting [`FinalizedValidator`] to
    /// [`OriginalPayload::process_outputs_owned_validator`].
    pub fn get_outputs_owned_validator(
        &self,
    ) -> OutputsOwnedValidator<impl Iterator<Item = ValidatorReference<ScriptBuf>>> {
        OutputsOwnedValidator::new(&self.psbt)
    }

    /// Processes a [`FinalizedValidator`] by verifying it and ensuring original PSBT has
    /// receiver owned outputs.
    ///
    /// An attacker can try to steal funds from the receiver inputs added to the payjoin
    /// by not including any receiver owned outputs. This check prevents that.
    ///
    /// Takes a [`FinalizedValidator`], verifies it is valid for the original PSBT, and checks
    /// that at least one output tested positive for being receiver owned. Get a
    /// [`OutputsOwnedValidator`] from [`OriginalPayload::get_outputs_owned_validator`] and
    /// use [`OutputsOwnedValidator::run`] or [`OutputsOwnedValidator::run_async`] to get a
    /// [`FinalizedValidator`].
    pub fn process_outputs_owned_validator(
        &self,
        finalized_validator: FinalizedValidator<
            impl IntoIterator<Item = TaggedValidatorReference<ScriptBuf, OutputOwnedTag>>,
            ScriptBuf,
            OutputOwnedTag,
        >,
    ) -> Result<common::WantsOutputs, Error> {
        let owned_output_indexes: Vec<usize> = finalized_validator
            .verify(self.psbt.outputs.len(), self.psbt.unsigned_tx.compute_ntxid())?
            .map(|tagged_ref| tagged_ref.get_index())
            .collect();

        if owned_output_indexes.is_empty() {
            return Err(InternalPayloadError::MissingPayment.into());
        }

        let mut params = self.params.clone();
        if let Some((_, additional_fee_output_index)) = params.additional_fee_contribution {
            // If the additional fee output index specified by the sender is pointing to a receiver output,
            // the receiver should ignore the parameter.
            // https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#optional-parameters
            if owned_output_indexes.contains(&additional_fee_output_index) {
                params.additional_fee_contribution = None;
            }
        }
        let original_payload = OriginalPayload { params, ..self.clone() };
        Ok(common::WantsOutputs::new(original_payload, owned_output_indexes))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use bitcoin::absolute::{LockTime, Time};
    use bitcoin::hashes::Hash;
    use bitcoin::key::{PublicKey, WPubkeyHash};
    use bitcoin::secp256k1::SECP256K1;
    use bitcoin::transaction::InputWeightPrediction;
    use bitcoin::{
        witness, Amount, PubkeyHash, ScriptBuf, ScriptHash, Sequence, Txid, WScriptHash,
        XOnlyPublicKey,
    };
    use payjoin_test_utils::{DUMMY20, DUMMY32, PARSED_ORIGINAL_PSBT, QUERY_PARAMS};

    use super::*;
    use crate::psbt::InternalPsbtInputError::InvalidScriptPubKey;
    use crate::psbt::NON_WITNESS_INPUT_WEIGHT;

    pub(crate) fn original_from_test_vector() -> OriginalPayload {
        let params = Params::from_query_str(QUERY_PARAMS, &[Version::One])
            .expect("Could not parse params from query str");
        OriginalPayload { psbt: PARSED_ORIGINAL_PSBT.clone(), params }
    }

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
        let p2pkh_pair = InputPair::new_p2pkh(utxo.clone(), outpoint).unwrap();
        assert_eq!(p2pkh_pair.txin.previous_output, outpoint);
        assert_eq!(p2pkh_pair.psbtin.non_witness_utxo.unwrap(), utxo);
        assert_eq!(
            p2pkh_pair.expected_weight,
            InputWeightPrediction::P2PKH_COMPRESSED_MAX.weight() + NON_WITNESS_INPUT_WEIGHT
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
        let invalid_p2pkh_pair = InputPair::new_p2pkh(utxo_with_p2sh.clone(), outpoint);
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
        let invalid_p2pkh_pair = InputPair::new_p2pkh(utxo_empty_outputs.clone(), outpoint);
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
        let redeem_script = ScriptBuf::new_p2sh(&ScriptHash::from_byte_array(DUMMY20));

        let p2sh_pair = InputPair::new_p2sh(utxo.clone(), outpoint, redeem_script.clone());

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
            InputPair::new_p2sh(utxo_with_p2pkh.clone(), outpoint, redeem_script.clone());
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
            InputPair::new_p2sh(utxo_empty_outputs.clone(), outpoint, redeem_script);
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
        let p2wpkh_txout = TxOut {
            value: Amount::from_sat(12345),
            script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array(DUMMY20)),
        };
        let p2wpkh_pair = InputPair::new_p2wpkh(p2wpkh_txout.clone(), outpoint).unwrap();
        assert_eq!(p2wpkh_pair.txin.previous_output, outpoint);
        assert_eq!(p2wpkh_pair.psbtin.witness_utxo.unwrap(), p2wpkh_txout);
        assert_eq!(
            p2wpkh_pair.expected_weight,
            InputWeightPrediction::P2WPKH_MAX.weight() + NON_WITNESS_INPUT_WEIGHT
        );

        let p2sh_txout = TxOut {
            value: Default::default(),
            script_pubkey: ScriptBuf::new_p2sh(&ScriptHash::all_zeros()),
        };
        assert_eq!(
            InputPair::new_p2wpkh(p2sh_txout, outpoint).err().unwrap(),
            PsbtInputError::from(InvalidScriptPubKey(AddressType::P2wpkh))
        )
    }

    #[test]
    fn create_p2wsh_input_pair() {
        let outpoint = OutPoint { txid: Txid::from_byte_array(DUMMY32), vout: 31 };
        let p2wsh_txout = TxOut {
            value: Amount::from_sat(12345),
            script_pubkey: ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array(DUMMY32)),
        };
        let expected_weight = Weight::from_wu(42);
        let p2wsh_pair = InputPair::new_p2wsh(p2wsh_txout.clone(), outpoint, expected_weight)
            .expect("valid params for p2wsh");

        assert_eq!(p2wsh_pair.txin.previous_output, outpoint);
        assert_eq!(p2wsh_pair.psbtin.witness_utxo.unwrap(), p2wsh_txout);
        assert_eq!(p2wsh_pair.expected_weight, expected_weight);

        let p2wsh_pair = InputPair::new(
            TxIn { previous_output: outpoint, ..Default::default() },
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
            InputPair::new_p2wsh(p2sh_txout, outpoint, expected_weight).err().unwrap(),
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
        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = pubkey_string.parse::<PublicKey>().expect("valid pubkey");
        let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);
        let p2tr_txout = TxOut {
            value: Amount::from_sat(12345),
            script_pubkey: ScriptBuf::new_p2tr(SECP256K1, xonly_pubkey, None),
        };

        // Expected weight for p2tr keyspend
        assert_eq!(
            DEFAULT_SIGHASH_KEY_SPEND_INPUT_WEIGHT,
            InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH.weight() + NON_WITNESS_INPUT_WEIGHT
        );
        let expected_key_weight = DEFAULT_SIGHASH_KEY_SPEND_INPUT_WEIGHT;
        let keyspend_pair = InputPair::new_p2tr_keyspend(p2tr_txout.clone(), outpoint).unwrap();
        assert_eq!(keyspend_pair.txin.previous_output, outpoint);
        let witness_utxo = keyspend_pair.psbtin.witness_utxo.clone().unwrap();
        assert_eq!(witness_utxo, p2tr_txout);
        assert_eq!(keyspend_pair.expected_weight, expected_key_weight);

        // Manual expected weight for p2tr scriptpath
        let script_expected_weight = Weight::from_wu(2048);
        let script_pair = InputPair::new_p2tr_scriptpath_spend(
            p2tr_txout.clone(),
            outpoint,
            script_expected_weight,
        )
        .unwrap();
        assert_eq!(script_pair.expected_weight, script_expected_weight);

        // P2TR without witness requires explicit weight (cannot auto-detect spend type)
        let txin = TxIn { previous_output: outpoint, ..Default::default() };
        let psbtin = psbt::Input { witness_utxo: Some(witness_utxo.clone()), ..Default::default() };
        let p2tr_pair = InputPair::new(txin.clone(), psbtin.clone(), None);
        assert_eq!(
            p2tr_pair.err().unwrap(),
            PsbtInputError::from(InternalPsbtInputError::from(InputWeightError::NotSupported))
        );

        // If UTXO is non-P2TR
        let p2sh_txout = TxOut {
            value: Default::default(),
            script_pubkey: ScriptBuf::new_p2sh(&ScriptHash::all_zeros()),
        };
        assert_eq!(
            InputPair::new_p2tr_keyspend(p2sh_txout, outpoint).err().unwrap(),
            PsbtInputError::from(InvalidScriptPubKey(AddressType::P2tr))
        )
    }

    #[test]
    fn p2tr_expected_weight_from_witness() {
        let outpoint = OutPoint { txid: Txid::from_byte_array(DUMMY32), vout: 31 };
        let pubkey_string = "0347ff3dacd07a1f43805ec6808e801505a6e18245178609972a68afbc2777ff2b";
        let pubkey = pubkey_string.parse::<PublicKey>().expect("valid pubkey");
        let xonly_pubkey = XOnlyPublicKey::from(pubkey.inner);
        let p2tr_txout = TxOut {
            value: Amount::from_sat(12345),
            script_pubkey: ScriptBuf::new_p2tr(SECP256K1, xonly_pubkey, None),
        };
        let base_txin = TxIn { previous_output: outpoint, ..Default::default() };
        let psbtin = psbt::Input { witness_utxo: Some(p2tr_txout.clone()), ..Default::default() };

        // P2tr with witness elements
        let mut script_witness = witness::Witness::new();
        script_witness.push(vec![0x03; 64]);
        script_witness.push(vec![0x04; 5]);
        script_witness.push(vec![0x05; 33]);
        let txin = TxIn { witness: script_witness.clone(), ..base_txin.clone() };
        let script_weight = Weight::from_non_witness_data_size(txin.base_size() as u64)
            + Weight::from_witness_data_size(script_witness.size() as u64);
        let pair = InputPair::new(txin, psbtin, None).expect("taproot witness provided");
        assert_eq!(pair.expected_weight, script_weight);

        // Witness stack supplied on the PSBT input instead of txin
        let txin = TxIn { witness: witness::Witness::new(), ..base_txin.clone() };
        let psbtin = psbt::Input {
            witness_utxo: Some(p2tr_txout.clone()),
            final_script_witness: Some(script_witness.clone()),
            ..Default::default()
        };
        let pair = InputPair::new(txin.clone(), psbtin.clone(), None)
            .expect("taproot witness provided via psbt input");
        assert_eq!(pair.expected_weight, script_weight);

        // Weight should not be manually provided if we can derive it from the witness stacks
        let err = InputPair::new(txin, psbtin, Some(script_weight)).unwrap_err();
        assert_eq!(err, PsbtInputError::from(InternalPsbtInputError::ProvidedUnnecessaryWeight));
    }

    #[test]
    fn test_identify_receiver_outputs() {
        let original = original_from_test_vector();

        // Simple check that it correctly identifies the owned vouts and leaves params unchanged
        let wants_outputs = original
            .clone()
            .identify_receiver_outputs(&mut |script| {
                Ok(script == &PARSED_ORIGINAL_PSBT.unsigned_tx.output[1].script_pubkey)
            })
            .expect("receiver outputs should be identified");
        assert_eq!(wants_outputs.owned_vouts, vec![1]);
        assert_eq!(wants_outputs.params, original.params);

        // No outputs belong to the receiver, it should error
        let wants_outputs = original
            .clone()
            .identify_receiver_outputs(&mut |_| Ok(false))
            .expect_err("should error");
        assert_eq!(wants_outputs.to_string(), "Protocol error: Missing payment.");

        // Fee contribution output belongs to the receiver, it should correctly identify owned
        // vouts and ignore the additional fee contribution param
        let params = Params {
            additional_fee_contribution: Some((Amount::from_sat(182), 1)),
            ..original.params
        };
        let original = OriginalPayload { params, ..original };
        let wants_outputs = original
            .identify_receiver_outputs(&mut |_| Ok(true))
            .expect("receiver outputs should be identified");
        assert_eq!(wants_outputs.owned_vouts, vec![0, 1]);
        assert_eq!(wants_outputs.params.additional_fee_contribution, None);
    }

    fn get_count<I>(mut iterator: impl Iterator<Item = I>) -> usize {
        let mut count: usize = 0;
        while iterator.next().is_some() {
            count += 1;
        }
        count
    }

    #[test]
    fn test_validator_run_and_verify() {
        let psbt = PARSED_ORIGINAL_PSBT.clone();
        let ntxid = psbt.unsigned_tx.compute_ntxid();
        let input_count = psbt.inputs.len();
        let output_count = psbt.unsigned_tx.output.len();

        let inputs_owned_finalized =
            InputsOwnedValidator::new(&psbt).unwrap().run(&mut |_script| Ok(true)).unwrap();
        let inputs_seen_finalized =
            InputsSeenValidator::new(&psbt).run(&mut |_outpoint| Ok(true)).unwrap();
        let outputs_owned_finalized =
            OutputsOwnedValidator::new(&psbt).run(&mut |_script| Ok(true)).unwrap();

        let inputs_owned_verified = inputs_owned_finalized.verify(input_count, ntxid);
        let inputs_seen_verified = inputs_seen_finalized.verify(input_count, ntxid);
        let outputs_owned_verified = outputs_owned_finalized.verify(output_count, ntxid);
        assert!(inputs_owned_verified.is_ok());
        assert!(inputs_seen_verified.is_ok());
        assert!(outputs_owned_verified.is_ok());
        assert_eq!(get_count(inputs_owned_verified.unwrap()), input_count);
        assert_eq!(get_count(inputs_seen_verified.unwrap()), input_count);
        assert_eq!(get_count(outputs_owned_verified.unwrap()), output_count);
    }

    #[tokio::test]
    async fn test_validator_run_async_and_verify() {
        let psbt = PARSED_ORIGINAL_PSBT.clone();
        let ntxid = psbt.unsigned_tx.compute_ntxid();
        let input_count = psbt.inputs.len();
        let output_count = psbt.unsigned_tx.output.len();

        let inputs_owned_finalized = InputsOwnedValidator::new(&psbt)
            .unwrap()
            .run_async(|_script| async { Ok(false) })
            .await
            .unwrap();
        let inputs_seen_finalized = InputsSeenValidator::new(&psbt)
            .run_async(|_outpoint| async { Ok(false) })
            .await
            .unwrap();
        let outputs_owned_finalized = OutputsOwnedValidator::new(&psbt)
            .run_async(|_script| async { Ok(false) })
            .await
            .unwrap();

        let inputs_owned_verified = inputs_owned_finalized.verify(input_count, ntxid);
        let inputs_seen_verified = inputs_seen_finalized.verify(input_count, ntxid);
        let outputs_owned_verified = outputs_owned_finalized.verify(output_count, ntxid);
        assert!(inputs_owned_verified.is_ok());
        assert!(inputs_seen_verified.is_ok());
        assert!(outputs_owned_verified.is_ok());
        assert_eq!(get_count(inputs_owned_verified.unwrap()), 0);
        assert_eq!(get_count(inputs_seen_verified.unwrap()), 0);
        assert_eq!(get_count(outputs_owned_verified.unwrap()), 0);
    }

    fn extract_validator_error<E>(res: Result<E, ImplementationError>) -> Option<String> {
        match res {
            Ok(_) => None,
            Err(e) => Some(e.to_string()),
        }
    }

    #[test]
    fn test_validator_run_returns_callback_error() {
        let psbt = PARSED_ORIGINAL_PSBT.clone();
        let callback_error_msg = "validator callback error";

        let inputs_owned_result = InputsOwnedValidator::new(&psbt)
            .unwrap()
            .run(&mut |_script| Err(ImplementationError::from(callback_error_msg)));
        let inputs_seen_result = InputsSeenValidator::new(&psbt)
            .run(&mut |_outpoint| Err(ImplementationError::from(callback_error_msg)));
        let outputs_owned_result = OutputsOwnedValidator::new(&psbt)
            .run(&mut |_script| Err(ImplementationError::from(callback_error_msg)));

        assert_eq!(extract_validator_error(inputs_owned_result).unwrap(), callback_error_msg);
        assert_eq!(extract_validator_error(inputs_seen_result).unwrap(), callback_error_msg);
        assert_eq!(extract_validator_error(outputs_owned_result).unwrap(), callback_error_msg);
    }

    #[tokio::test]
    async fn test_validator_run_async_returns_callback_error() {
        let psbt = PARSED_ORIGINAL_PSBT.clone();
        let callback_error_msg = "validator callback error";

        let inputs_owned_result = InputsOwnedValidator::new(&psbt)
            .unwrap()
            .run_async(|_script| async { Err(ImplementationError::from(callback_error_msg)) })
            .await;
        let inputs_seen_result = InputsSeenValidator::new(&psbt)
            .run_async(|_outpoint| async { Err(ImplementationError::from(callback_error_msg)) })
            .await;
        let outputs_owned_result = OutputsOwnedValidator::new(&psbt)
            .run_async(|_script| async { Err(ImplementationError::from(callback_error_msg)) })
            .await;

        assert_eq!(extract_validator_error(inputs_owned_result).unwrap(), callback_error_msg);
        assert_eq!(extract_validator_error(inputs_seen_result).unwrap(), callback_error_msg);
        assert_eq!(extract_validator_error(outputs_owned_result).unwrap(), callback_error_msg);
    }

    #[test]
    fn test_finalized_validator_verify_errors() {
        let psbt = PARSED_ORIGINAL_PSBT.clone();
        let ntxid = psbt.unsigned_tx.compute_ntxid();
        let input_count = psbt.inputs.len();

        // Wrong identifier
        let wrong_ntxid = sha256d::Hash::hash(b"wrong identifier");
        let finalized =
            InputsOwnedValidator::new(&psbt).unwrap().run(&mut |_script| Ok(true)).unwrap();
        let verify_result = finalized.verify(input_count, wrong_ntxid);
        assert_eq!(
            extract_validator_error(verify_result).unwrap(),
            "Validation error: encountered unexpected identifier",
        );

        // Wrong count
        let finalized =
            InputsOwnedValidator::new(&psbt).unwrap().run(&mut |_script| Ok(true)).unwrap();
        let verify_result = finalized.verify(input_count + 1, ntxid);
        assert_eq!(
            extract_validator_error(verify_result).unwrap(),
            "Validation error: encountered unexpected number of references"
        );
    }
}
