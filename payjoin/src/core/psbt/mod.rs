//! Utilities to make work with PSBTs easier

use std::collections::BTreeMap;
use std::fmt;

use bitcoin::address::FromScriptError;
use bitcoin::psbt::{Psbt, PsbtSighashType};
use bitcoin::script::Instruction;
use bitcoin::transaction::InputWeightPrediction;
use bitcoin::{bip32, psbt, Address, AddressType, Network, Script, TxIn, TxOut, Weight};
/// Shared non-witness weight for txid (32), index (4), and sequence (4) fields.
/// We only need to add the weight of the txid: 32, index: 4 and sequence: 4 as rust_bitcoin
/// already accounts for the scriptsig length when calculating InputWeightPrediction
/// <https://docs.rs/bitcoin/latest/src/bitcoin/blockdata/transaction.rs.html#1621>
pub(crate) const NON_WITNESS_INPUT_WEIGHT: Weight = Weight::from_non_witness_data_size(32 + 4 + 4);

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InconsistentPsbt {
    UnequalInputCounts { tx_ins: usize, psbt_ins: usize },
    UnequalOutputCounts { tx_outs: usize, psbt_outs: usize },
}

impl fmt::Display for InconsistentPsbt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InconsistentPsbt::UnequalInputCounts { tx_ins, psbt_ins, } => write!(f, "The number of PSBT inputs ({psbt_ins}) doesn't equal to the number of unsigned transaction inputs ({tx_ins})"),
            InconsistentPsbt::UnequalOutputCounts { tx_outs, psbt_outs, } => write!(f, "The number of PSBT outputs ({psbt_outs}) doesn't equal to the number of unsigned transaction outputs ({tx_outs})"),
        }
    }
}

impl std::error::Error for InconsistentPsbt {}

/// Our Psbt type for validation and utilities
pub(crate) trait PsbtExt: Sized {
    fn inputs_mut(&mut self) -> &mut [psbt::Input];
    fn outputs_mut(&mut self) -> &mut [psbt::Output];
    fn xpub_mut(
        &mut self,
    ) -> &mut BTreeMap<bip32::Xpub, (bip32::Fingerprint, bip32::DerivationPath)>;
    fn proprietary_mut(&mut self) -> &mut BTreeMap<psbt::raw::ProprietaryKey, Vec<u8>>;
    fn unknown_mut(&mut self) -> &mut BTreeMap<psbt::raw::Key, Vec<u8>>;
    fn input_pairs(&self) -> Box<dyn Iterator<Item = InternalInputPair<'_>> + '_>;
    // guarantees that length of psbt input matches that of unsigned_tx inputs and same
    /// thing for outputs.
    fn validate(self) -> Result<Self, InconsistentPsbt>;
    fn validate_input_utxos(&self) -> Result<(), PsbtInputsError>;
}

impl PsbtExt for Psbt {
    fn inputs_mut(&mut self) -> &mut [psbt::Input] { &mut self.inputs }

    fn outputs_mut(&mut self) -> &mut [psbt::Output] { &mut self.outputs }

    fn xpub_mut(
        &mut self,
    ) -> &mut BTreeMap<bip32::Xpub, (bip32::Fingerprint, bip32::DerivationPath)> {
        &mut self.xpub
    }

    fn proprietary_mut(&mut self) -> &mut BTreeMap<psbt::raw::ProprietaryKey, Vec<u8>> {
        &mut self.proprietary
    }

    fn unknown_mut(&mut self) -> &mut BTreeMap<psbt::raw::Key, Vec<u8>> { &mut self.unknown }

    fn input_pairs(&self) -> Box<dyn Iterator<Item = InternalInputPair<'_>> + '_> {
        Box::new(
            self.unsigned_tx
                .input
                .iter()
                .zip(&self.inputs)
                .map(|(txin, psbtin)| InternalInputPair { txin, psbtin }),
        )
    }

    fn validate(self) -> Result<Self, InconsistentPsbt> {
        let tx_ins = self.unsigned_tx.input.len();
        let psbt_ins = self.inputs.len();
        let tx_outs = self.unsigned_tx.output.len();
        let psbt_outs = self.outputs.len();

        if psbt_ins != tx_ins {
            Err(InconsistentPsbt::UnequalInputCounts { tx_ins, psbt_ins })
        } else if psbt_outs != tx_outs {
            Err(InconsistentPsbt::UnequalOutputCounts { tx_outs, psbt_outs })
        } else {
            Ok(self)
        }
    }

    fn validate_input_utxos(&self) -> Result<(), PsbtInputsError> {
        self.input_pairs().enumerate().try_for_each(|(index, input)| {
            input.validate_utxo().map_err(|error| PsbtInputsError { index, error })
        })
    }
}

// input script: 0x160014{20-byte-key-hash} = 23 bytes
// witness: <signature> <pubkey> = 72, 33 bytes
// https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#p2wpkh-nested-in-bip16-p2sh
const NESTED_P2WPKH_MAX: InputWeightPrediction = InputWeightPrediction::from_slice(23, &[72, 33]);

#[derive(Clone, Debug)]
pub(crate) struct InternalInputPair<'a> {
    pub txin: &'a TxIn,
    pub psbtin: &'a psbt::Input,
}

impl InternalInputPair<'_> {
    /// Returns the [`TxOut`] associated with the input.
    pub fn previous_txout(&self) -> Result<&TxOut, PrevTxOutError> {
        match (&self.psbtin.non_witness_utxo, &self.psbtin.witness_utxo) {
            (None, None) => Err(PrevTxOutError::MissingUtxoInformation),
            // Prefer the `non_witness_utxo`: its txid is committed to by
            // `previous_output`, so it authenticates the spent `TxOut`, unlike a bare
            // `witness_utxo`.
            (Some(tx), _) => {
                let vout: usize = self.txin.previous_output.vout.try_into().map_err(|_| {
                    PrevTxOutError::IndexOutOfBounds {
                        output_count: tx.output.len(),
                        index: self.txin.previous_output.vout,
                    }
                })?;
                tx.output.get(vout).ok_or(PrevTxOutError::IndexOutOfBounds {
                    output_count: tx.output.len(),
                    index: self.txin.previous_output.vout,
                })
            }
            (None, Some(txout)) => Ok(txout),
        }
    }

    /// Validates that [`TxIn`] and the applicable UTXO field(s) of the [`psbt::Input`] refer to the same UTXO.
    pub fn validate_utxo(&self) -> Result<(), InternalPsbtInputError> {
        match (&self.psbtin.non_witness_utxo, &self.psbtin.witness_utxo) {
            (None, None) =>
                Err(InternalPsbtInputError::PrevTxOut(PrevTxOutError::MissingUtxoInformation)),
            (Some(tx), None) if tx.compute_txid() == self.txin.previous_output.txid => tx
                .output
                .get::<usize>(self.txin.previous_output.vout.try_into().map_err(|_| {
                    PrevTxOutError::IndexOutOfBounds {
                        output_count: tx.output.len(),
                        index: self.txin.previous_output.vout,
                    }
                })?)
                .ok_or_else(|| {
                    PrevTxOutError::IndexOutOfBounds {
                        output_count: tx.output.len(),
                        index: self.txin.previous_output.vout,
                    }
                    .into()
                })
                .map(drop),
            (Some(_), None) => Err(InternalPsbtInputError::UnequalTxid),
            (None, Some(_)) => Ok(()),
            (Some(tx), Some(witness_txout))
                if tx.compute_txid() == self.txin.previous_output.txid =>
            {
                let non_witness_txout = tx
                    .output
                    .get::<usize>(self.txin.previous_output.vout.try_into().map_err(|_| {
                        PrevTxOutError::IndexOutOfBounds {
                            output_count: tx.output.len(),
                            index: self.txin.previous_output.vout,
                        }
                    })?)
                    .ok_or(PrevTxOutError::IndexOutOfBounds {
                        output_count: tx.output.len(),
                        index: self.txin.previous_output.vout,
                    })?;
                if witness_txout == non_witness_txout {
                    Ok(())
                } else {
                    Err(InternalPsbtInputError::SegWitTxOutMismatch)
                }
            }
            (Some(_), Some(_)) => Err(InternalPsbtInputError::UnequalTxid),
        }
    }

    /// Returns the scriptPubKey address type of the UTXO this input is pointing to.
    pub fn address_type(&self) -> Result<AddressType, AddressTypeError> {
        let txo = self.previous_txout()?;
        // HACK: Network doesn't matter for our use case of only getting the address type
        // but is required in the `from_script` interface. Hardcoded to mainnet.
        Address::from_script(&txo.script_pubkey, Network::Bitcoin)?
            .address_type()
            .ok_or(AddressTypeError::UnknownAddressType)
    }

    /// Returns the expected weight of this input based on the address type of the UTXO it is pointing to.
    pub fn expected_input_weight(&self) -> Result<Weight, InputWeightError> {
        use bitcoin::AddressType::*;

        // Get the input weight prediction corresponding to spending an output of this address type
        let iwp = match self.address_type()? {
            P2pkh => Ok(InputWeightPrediction::P2PKH_COMPRESSED_MAX),
            P2sh => {
                // redeemScript can be extracted from scriptSig for signed P2SH inputs
                let redeem_script = if let Some(ref script_sig) = self.psbtin.final_script_sig {
                    script_sig.redeem_script()
                    // try the PSBT redeem_script field for unsigned inputs.
                } else {
                    self.psbtin.redeem_script.as_ref().map(|script| script.as_ref())
                };
                match redeem_script {
                    // Nested segwit p2wpkh.
                    Some(script) if script.is_witness_program() && script.is_p2wpkh() =>
                        Ok(NESTED_P2WPKH_MAX),
                    // Other script or witness program.
                    Some(_) => Err(InputWeightError::NotSupported),
                    // No redeem script provided. Cannot determine the script type.
                    None => Err(InputWeightError::NoRedeemScript),
                }
            }
            P2wpkh => Ok(InputWeightPrediction::P2WPKH_MAX),
            P2wsh =>
                if !self.txin.witness.is_empty() {
                    Ok(InputWeightPrediction::new(
                        0,
                        self.txin.witness.iter().map(|el| el.len()).collect::<Vec<_>>(),
                    ))
                } else {
                    let iwp = self
                        .psbtin
                        .final_script_witness
                        .as_ref()
                        .filter(|w| !w.is_empty())
                        .map(|w| {
                            InputWeightPrediction::new(
                                0,
                                w.iter().map(|el| el.len()).collect::<Vec<_>>(),
                            )
                        })
                        .ok_or(InputWeightError::NotSupported)?;
                    Ok(iwp)
                },
            P2tr => {
                let witness = if !self.txin.witness.is_empty() {
                    Some(&self.txin.witness)
                } else {
                    self.psbtin.final_script_witness.as_ref().filter(|w| !w.is_empty())
                };
                match witness {
                    Some(w) => Ok(InputWeightPrediction::new(
                        0,
                        w.iter().map(|el| el.len()).collect::<Vec<_>>(),
                    )),
                    None => Err(InputWeightError::NotSupported),
                }
            }
            _ => Err(AddressTypeError::UnknownAddressType.into()),
        }?;
        // Lengths of txid, index and sequence: (32, 4, 4).
        let input_weight = iwp.weight() + NON_WITNESS_INPUT_WEIGHT;
        Ok(input_weight)
    }

    /// Returns the sighash type carried by each signature in this input's
    /// finalized signature data (`final_script_sig` and
    /// `final_script_witness`), or an error if a signature is malformed.
    ///
    /// The sighash type a signer actually used is the trailing byte of the
    /// signature itself, not the optional `PSBT_IN_SIGHASH_TYPE` field, which
    /// finalizers clear. An input that is not finalized yields an empty list.
    ///
    /// Which stack elements hold signatures is decided by the spent
    /// scriptPubKey (and the redeemScript for P2SH). For single-key templates
    /// the signature position is fixed and must parse. For script templates
    /// every element other than the script itself is inspected and anything
    /// that parses as a signature is reported.
    pub fn final_signature_sighash_types(
        &self,
    ) -> Result<Vec<PsbtSighashType>, FinalSignatureError> {
        let script_pubkey = &self.previous_txout()?.script_pubkey;
        let script_sig = self.psbtin.final_script_sig.as_deref().filter(|s| !s.is_empty());
        let witness = self.psbtin.final_script_witness.as_ref().filter(|w| !w.is_empty());

        let script_sig_pushes = |script: &Script| -> Result<Vec<Vec<u8>>, FinalSignatureError> {
            script
                .instructions()
                .filter_map(|instruction| match instruction {
                    Ok(Instruction::PushBytes(bytes)) => Some(Ok(bytes.as_bytes().to_vec())),
                    Ok(Instruction::Op(_)) => None,
                    Err(e) => Some(Err(e.into())),
                })
                .collect()
        };

        let redeem_script =
            if script_pubkey.is_p2sh() { script_sig.and_then(Script::redeem_script) } else { None };
        let witness_program = redeem_script.or(Some(script_pubkey));

        match witness_program {
            Some(program) if program.is_p2wpkh() => match witness {
                Some(witness) => {
                    let signature = witness.nth(0).ok_or(FinalSignatureError::NotASignature)?;
                    Ok(vec![required_signature_sighash_type(signature)?])
                }
                None => Ok(Vec::new()),
            },
            Some(program) if program.is_p2wsh() => match witness {
                // The last element is the witnessScript.
                Some(witness) => scan_for_signatures(witness.iter().take(witness.len() - 1)),
                None => Ok(Vec::new()),
            },
            Some(program) if program.is_p2tr() && redeem_script.is_none() => match witness {
                Some(witness) => match witness.taproot_control_block() {
                    None => {
                        let signature = witness.nth(0).ok_or(FinalSignatureError::NotASignature)?;
                        Ok(vec![required_signature_sighash_type(signature)?])
                    }
                    // Script path: skip the leaf script, the control block and,
                    // when present, the annex.
                    Some(_) => {
                        let trailing = 2 + usize::from(witness.taproot_annex().is_some());
                        scan_for_signatures(witness.iter().take(witness.len() - trailing))
                    }
                },
                None => Ok(Vec::new()),
            },
            _ if script_pubkey.is_p2pkh() => match script_sig {
                Some(script_sig) => {
                    let pushes = script_sig_pushes(script_sig)?;
                    let signature = pushes.first().ok_or(FinalSignatureError::NotASignature)?;
                    Ok(vec![required_signature_sighash_type(signature)?])
                }
                None => Ok(Vec::new()),
            },
            // Bare scripts, P2PK, and P2SH wrapping something other than a
            // witness program: signatures may sit anywhere in the scriptSig
            // (or the witness, for an unknown witness program). For P2SH the
            // last push is the redeemScript.
            _ => {
                let mut pushes = match script_sig {
                    Some(script_sig) => script_sig_pushes(script_sig)?,
                    None => Vec::new(),
                };
                if redeem_script.is_some() {
                    pushes.pop();
                }
                let mut sighash_types = scan_for_signatures(pushes.iter().map(Vec::as_slice))?;
                if let Some(witness) = witness {
                    sighash_types.extend(scan_for_signatures(witness.iter())?);
                }
                Ok(sighash_types)
            }
        }
    }
}

/// Parses a stack element that is required to be a signature and returns its
/// sighash type.
fn required_signature_sighash_type(bytes: &[u8]) -> Result<PsbtSighashType, FinalSignatureError> {
    signature_sighash_type(bytes)?.ok_or(FinalSignatureError::NotASignature)
}

/// Returns the sighash type of every stack element that parses as a
/// signature, in stack order.
///
/// A data push that happens to parse as a DER signature is reported as one.
/// That can only make the caller reject an input it might have accepted, which
/// is the safe direction when the alternative is missing a real signature.
fn scan_for_signatures<'a>(
    elements: impl Iterator<Item = &'a [u8]>,
) -> Result<Vec<PsbtSighashType>, FinalSignatureError> {
    elements.filter_map(|bytes| signature_sighash_type(bytes).transpose()).collect()
}

/// Returns the sighash type of a stack element if it is a signature.
///
/// ECDSA signatures are DER followed by a sighash byte; Schnorr signatures are
/// 64 bytes (`SIGHASH_DEFAULT`) or 65 bytes with a trailing sighash byte.
/// `Ok(None)` means the element is not a signature. An element that is
/// recognizably a signature but carries an invalid sighash byte is an error
/// rather than `None`, so it cannot pass as data.
fn signature_sighash_type(bytes: &[u8]) -> Result<Option<PsbtSighashType>, FinalSignatureError> {
    if let Some((_, der)) = bytes.split_last() {
        if bitcoin::secp256k1::ecdsa::Signature::from_der(der).is_ok() {
            let signature = bitcoin::ecdsa::Signature::from_slice(bytes)?;
            return Ok(Some(signature.sighash_type.into()));
        }
    }
    if matches!(bytes.len(), 64 | 65) {
        let signature = bitcoin::taproot::Signature::from_slice(bytes)?;
        return Ok(Some(signature.sighash_type.into()));
    }
    Ok(None)
}

/// Error reading the signatures out of a finalized PSBT input.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FinalSignatureError {
    PrevTxOut(PrevTxOutError),
    Script(bitcoin::script::Error),
    Ecdsa(bitcoin::ecdsa::Error),
    Taproot(bitcoin::taproot::SigFromSliceError),
    /// The stack element where the script template places a signature does
    /// not parse as one.
    NotASignature,
}

impl fmt::Display for FinalSignatureError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::PrevTxOut(e) => write!(f, "invalid previous transaction output: {e}"),
            Self::Script(e) => write!(f, "malformed final scriptSig: {e}"),
            Self::Ecdsa(e) => write!(f, "malformed ECDSA signature: {e}"),
            Self::Taproot(e) => write!(f, "malformed Schnorr signature: {e}"),
            Self::NotASignature => write!(f, "expected a signature in the finalized input data"),
        }
    }
}

impl std::error::Error for FinalSignatureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PrevTxOut(e) => Some(e),
            Self::Script(e) => Some(e),
            Self::Ecdsa(e) => Some(e),
            Self::Taproot(e) => Some(e),
            Self::NotASignature => None,
        }
    }
}

impl From<PrevTxOutError> for FinalSignatureError {
    fn from(value: PrevTxOutError) -> Self { Self::PrevTxOut(value) }
}

impl From<bitcoin::script::Error> for FinalSignatureError {
    fn from(value: bitcoin::script::Error) -> Self { Self::Script(value) }
}

impl From<bitcoin::ecdsa::Error> for FinalSignatureError {
    fn from(value: bitcoin::ecdsa::Error) -> Self { Self::Ecdsa(value) }
}

impl From<bitcoin::taproot::SigFromSliceError> for FinalSignatureError {
    fn from(value: bitcoin::taproot::SigFromSliceError) -> Self { Self::Taproot(value) }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PrevTxOutError {
    MissingUtxoInformation,
    IndexOutOfBounds { output_count: usize, index: u32 },
}

impl fmt::Display for PrevTxOutError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PrevTxOutError::MissingUtxoInformation => write!(f, "missing UTXO information"),
            PrevTxOutError::IndexOutOfBounds { output_count, index } => {
                write!(f, "index {index} out of bounds (number of outputs: {output_count})")
            }
        }
    }
}

impl std::error::Error for PrevTxOutError {}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InternalPsbtInputError {
    PrevTxOut(PrevTxOutError),
    UnequalTxid,
    /// TxOut provided in `segwit_utxo` doesn't match the one in `non_segwit_utxo`
    SegWitTxOutMismatch,
    AddressType(AddressTypeError),
    InvalidScriptPubKey(AddressType),
    WeightError(InputWeightError),
    /// Weight was provided but can be calculated from available information
    ProvidedUnnecessaryWeight,
}

impl fmt::Display for InternalPsbtInputError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::PrevTxOut(_) => write!(f, "invalid previous transaction output"),
            Self::UnequalTxid => write!(f, "transaction ID of previous transaction doesn't match one specified in input spending it"),
            Self::SegWitTxOutMismatch => write!(f, "transaction output provided in SegWit UTXO field doesn't match the one in non-SegWit UTXO field"),
            Self::AddressType(_) => write!(f, "invalid address type"),
            Self::InvalidScriptPubKey(e) => write!(f, "provided script was not a valid type of {e}"),
            Self::WeightError(e) => write!(f, "{e}"),
            Self::ProvidedUnnecessaryWeight => write!(f, "weight was provided but can be calculated from available information"),
        }
    }
}

impl std::error::Error for InternalPsbtInputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PrevTxOut(error) => Some(error),
            Self::UnequalTxid => None,
            Self::SegWitTxOutMismatch => None,
            Self::AddressType(error) => Some(error),
            Self::InvalidScriptPubKey(_) => None,
            Self::WeightError(error) => Some(error),
            Self::ProvidedUnnecessaryWeight => None,
        }
    }
}

impl From<PrevTxOutError> for InternalPsbtInputError {
    fn from(value: PrevTxOutError) -> Self { InternalPsbtInputError::PrevTxOut(value) }
}

impl From<AddressTypeError> for InternalPsbtInputError {
    fn from(value: AddressTypeError) -> Self { Self::AddressType(value) }
}

impl From<InputWeightError> for InternalPsbtInputError {
    fn from(value: InputWeightError) -> Self { Self::WeightError(value) }
}

#[derive(Debug, PartialEq, Eq)]
pub struct PsbtInputError(InternalPsbtInputError);

impl From<InternalPsbtInputError> for PsbtInputError {
    fn from(e: InternalPsbtInputError) -> Self { PsbtInputError(e) }
}

impl fmt::Display for PsbtInputError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { write!(f, "{}", self.0) }
}

impl std::error::Error for PsbtInputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }
}

#[derive(Debug, PartialEq)]
pub struct PsbtInputsError {
    index: usize,
    error: InternalPsbtInputError,
}

impl fmt::Display for PsbtInputsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid PSBT input #{}", self.index)
    }
}

impl std::error::Error for PsbtInputsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.error) }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AddressTypeError {
    PrevTxOut(PrevTxOutError),
    InvalidScript(FromScriptError),
    UnknownAddressType,
    FeeRateOverflow,
}

impl fmt::Display for AddressTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::PrevTxOut(_) => write!(f, "invalid previous transaction output"),
            Self::InvalidScript(_) => write!(f, "invalid script"),
            Self::UnknownAddressType => write!(f, "unknown address type"),
            Self::FeeRateOverflow => write!(f, "fee rate overflow"),
        }
    }
}

impl std::error::Error for AddressTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PrevTxOut(error) => Some(error),
            Self::InvalidScript(error) => Some(error),
            Self::UnknownAddressType => None,
            Self::FeeRateOverflow => None,
        }
    }
}

impl From<PrevTxOutError> for AddressTypeError {
    fn from(value: PrevTxOutError) -> Self { Self::PrevTxOut(value) }
}

impl From<FromScriptError> for AddressTypeError {
    fn from(value: FromScriptError) -> Self { Self::InvalidScript(value) }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InputWeightError {
    AddressType(AddressTypeError),
    NoRedeemScript,
    NotSupported,
}

impl fmt::Display for InputWeightError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::AddressType(_) => write!(f, "invalid address type"),
            Self::NoRedeemScript => write!(f, "p2sh input missing a redeem script"),
            Self::NotSupported => write!(f, "weight prediction not supported"),
        }
    }
}

impl std::error::Error for InputWeightError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AddressType(error) => Some(error),
            Self::NoRedeemScript => None,
            Self::NotSupported => None,
        }
    }
}
impl From<AddressTypeError> for InputWeightError {
    fn from(value: AddressTypeError) -> Self { Self::AddressType(value) }
}

#[cfg(test)]
mod test {
    use bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_PUSHNUM_2};
    use bitcoin::psbt::PsbtSighashType;
    use bitcoin::script::{Builder, PushBytes};
    use bitcoin::secp256k1::{PublicKey, SecretKey, SECP256K1};
    use bitcoin::sighash::{EcdsaSighashType, TapSighashType};
    use bitcoin::{psbt, Amount, Psbt, ScriptBuf, Transaction, TxIn, TxOut, Witness};
    use payjoin_test_utils::PARSED_ORIGINAL_PSBT;

    use crate::psbt::{
        FinalSignatureError, InputWeightError, InternalInputPair, InternalPsbtInputError, PsbtExt,
    };

    #[test]
    fn validate_input_utxos() {
        let psbt: Psbt = PARSED_ORIGINAL_PSBT.clone();
        let validated_pairs = psbt.validate_input_utxos();
        assert!(validated_pairs.is_ok());
    }

    #[test]
    fn input_pairs_validate_witness_utxo() {
        let psbt: Psbt = PARSED_ORIGINAL_PSBT.clone();
        let txin = &psbt.unsigned_tx.input[0];
        let psbtin = &psbt.inputs[0];

        let pair: InternalInputPair = InternalInputPair { txin, psbtin };
        assert!(pair.validate_utxo().is_ok());
    }

    #[test]
    fn input_pairs_validate_non_witness_utxo() {
        // This test checks each variation of the validate_utxo match block with no
        // non_witness_utxo
        let psbt: Psbt = PARSED_ORIGINAL_PSBT.clone();
        let raw_tx = "010000000001015721029046ec1840d5bc8f4e59ae8ac4b576191d5e7994c8d1c44ddeaffc176c0300000000fdffffff018e8d00000000000017a9144a87748bc7bcfee8290e36700eeca3112f53ecbe870140239d1975e0fc9b8345bce9a170a0224cf8eb327bfcaccf0f8b9434d17345579e4dcbb68f7be39eac7987dfaa08293b11fdc76ac28e26bd85e99a46b69675418100000000";

        let mut txin = psbt.unsigned_tx.input[0].clone();
        let mut psbtin = psbt.inputs[0].clone();

        let transaction: Transaction = bitcoin::consensus::encode::deserialize_hex(raw_tx).unwrap();
        psbtin.non_witness_utxo = Some(transaction.clone());
        psbtin.witness_utxo = None;
        txin.previous_output.txid = transaction.compute_txid();

        let pair: InternalInputPair = InternalInputPair { txin: &txin, psbtin: &psbtin };
        assert!(pair.validate_utxo().is_ok());
    }

    #[test]
    fn input_pairs_unequal_txid() {
        // This test checks each variation of the validate_utxo match block where is it expected to
        // return an unequal_txid error
        let psbt: Psbt = PARSED_ORIGINAL_PSBT.clone();
        let raw_tx = "010000000001015721029046ec1840d5bc8f4e59ae8ac4b576191d5e7994c8d1c44ddeaffc176c0300000000fdffffff018e8d00000000000017a9144a87748bc7bcfee8290e36700eeca3112f53ecbe870140239d1975e0fc9b8345bce9a170a0224cf8eb327bfcaccf0f8b9434d17345579e4dcbb68f7be39eac7987dfaa08293b11fdc76ac28e26bd85e99a46b69675418100000000";

        let txin = &psbt.unsigned_tx.input[0];
        let mut psbtin = psbt.inputs[0].clone();

        let transaction: Transaction = bitcoin::consensus::encode::deserialize_hex(raw_tx).unwrap();
        psbtin.non_witness_utxo = Some(transaction);

        let pair: InternalInputPair = InternalInputPair { txin, psbtin: &psbtin };
        let validated_utxo = pair.validate_utxo();
        assert_eq!(validated_utxo.unwrap_err(), InternalPsbtInputError::UnequalTxid);

        let txin = &psbt.unsigned_tx.input[0];
        let mut psbtin = psbt.inputs[0].clone();

        let transaction: Transaction = bitcoin::consensus::encode::deserialize_hex(raw_tx).unwrap();
        psbtin.non_witness_utxo = Some(transaction);
        psbtin.witness_utxo = None;

        let pair: InternalInputPair = InternalInputPair { txin, psbtin: &psbtin };
        let validated_utxo = pair.validate_utxo();
        assert_eq!(validated_utxo.unwrap_err(), InternalPsbtInputError::UnequalTxid);
    }

    #[test]
    fn input_pairs_txout_mismatch() {
        let psbt: Psbt = PARSED_ORIGINAL_PSBT.clone();
        let raw_tx = "010000000001015721029046ec1840d5bc8f4e59ae8ac4b576191d5e7994c8d1c44ddeaffc176c0300000000fdffffff018e8d00000000000017a9144a87748bc7bcfee8290e36700eeca3112f53ecbe870140239d1975e0fc9b8345bce9a170a0224cf8eb327bfcaccf0f8b9434d17345579e4dcbb68f7be39eac7987dfaa08293b11fdc76ac28e26bd85e99a46b69675418100000000";

        let mut txin = psbt.unsigned_tx.input[0].clone();
        let mut psbtin = psbt.inputs[0].clone();

        let transaction: Transaction = bitcoin::consensus::encode::deserialize_hex(raw_tx).unwrap();
        psbtin.non_witness_utxo = Some(transaction.clone());
        txin.previous_output.txid = transaction.compute_txid();

        let pair: InternalInputPair = InternalInputPair { txin: &txin, psbtin: &psbtin };
        let validated_utxo = pair.validate_utxo();
        assert_eq!(validated_utxo.unwrap_err(), InternalPsbtInputError::SegWitTxOutMismatch);
    }

    #[test]
    fn previous_txout_prefers_authenticated_non_witness_utxo() {
        // When both UTXO fields are present, `previous_txout` must return the `TxOut`
        // derived from the txid-authenticated `non_witness_utxo`, not the
        // `witness_utxo`.
        let psbt: Psbt = PARSED_ORIGINAL_PSBT.clone();
        let raw_tx = "010000000001015721029046ec1840d5bc8f4e59ae8ac4b576191d5e7994c8d1c44ddeaffc176c0300000000fdffffff018e8d00000000000017a9144a87748bc7bcfee8290e36700eeca3112f53ecbe870140239d1975e0fc9b8345bce9a170a0224cf8eb327bfcaccf0f8b9434d17345579e4dcbb68f7be39eac7987dfaa08293b11fdc76ac28e26bd85e99a46b69675418100000000";
        let transaction: Transaction = bitcoin::consensus::encode::deserialize_hex(raw_tx).unwrap();

        let mut txin = psbt.unsigned_tx.input[0].clone();
        let mut psbtin = psbt.inputs[0].clone();

        psbtin.non_witness_utxo = Some(transaction.clone());
        txin.previous_output.txid = transaction.compute_txid();
        txin.previous_output.vout = 0;
        let authenticated_spk = transaction.output[0].script_pubkey.clone();

        let mismatched_spk =
            ScriptBuf::from_hex("00140000000000000000000000000000000000000000").unwrap();
        assert_ne!(authenticated_spk, mismatched_spk);
        psbtin.witness_utxo = Some(TxOut {
            value: transaction.output[0].value,
            script_pubkey: mismatched_spk.clone(),
        });

        let pair: InternalInputPair = InternalInputPair { txin: &txin, psbtin: &psbtin };

        assert_eq!(pair.validate_utxo().unwrap_err(), InternalPsbtInputError::SegWitTxOutMismatch);
        assert_eq!(pair.previous_txout().unwrap().script_pubkey, authenticated_spk);
    }

    #[test]
    fn expected_input_weight() {
        let psbt: Psbt = PARSED_ORIGINAL_PSBT.clone();
        let txin = &psbt.unsigned_tx.input[0];
        let psbtin = psbt.inputs[0].clone();

        let pair: InternalInputPair = InternalInputPair { txin, psbtin: &psbtin };
        let weight = pair.expected_input_weight();
        assert!(weight.is_ok());

        let mut psbtin = psbt.inputs[0].clone();
        psbtin.final_script_sig = Some(
            ScriptBuf::from_hex(
                "22002065f91a53cb7120057db3d378bd0f7d944167d43a7dcbff15d6afc4823f1d3ed3",
            )
            .unwrap(),
        );
        let pair: InternalInputPair = InternalInputPair { txin, psbtin: &psbtin };
        let weight = pair.expected_input_weight();
        assert_eq!(weight.unwrap_err(), InputWeightError::NotSupported);

        let mut psbtin = psbt.inputs[0].clone();
        psbtin.final_script_sig = None;
        let pair: InternalInputPair = InternalInputPair { txin, psbtin: &psbtin };
        let weight = pair.expected_input_weight();
        assert_eq!(weight.unwrap_err(), InputWeightError::NoRedeemScript)
    }

    /// The finalized ECDSA signature from the Original PSBT fixture with its
    /// trailing sighash byte replaced by `flag`.
    fn der_signature_with_flag(flag: u8) -> Vec<u8> {
        let witness = PARSED_ORIGINAL_PSBT.inputs[0]
            .final_script_witness
            .as_ref()
            .expect("fixture input is finalized with a witness");
        let mut signature = witness.nth(0).expect("fixture witness carries a signature").to_vec();
        *signature.last_mut().expect("signature has a sighash byte") = flag;
        signature
    }

    fn push(bytes: &[u8]) -> &PushBytes {
        <&PushBytes>::try_from(bytes).expect("fixture data fits a push")
    }

    fn pubkey(secret: u8) -> PublicKey {
        PublicKey::from_secret_key(
            SECP256K1,
            &SecretKey::from_slice(&[secret; 32]).expect("nonzero secret is valid"),
        )
    }

    /// A 2-of-2 multisig witnessScript (or redeemScript).
    fn multisig_2_of_2() -> ScriptBuf {
        Builder::new()
            .push_opcode(OP_PUSHNUM_2)
            .push_slice(pubkey(1).serialize())
            .push_slice(pubkey(2).serialize())
            .push_opcode(OP_PUSHNUM_2)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script()
    }

    /// The finalized witness of a 2-of-2 multisig spend: the CHECKMULTISIG
    /// dummy, both signatures, then the witnessScript.
    fn multisig_witness(flag_a: u8, flag_b: u8, witness_script: &ScriptBuf) -> Witness {
        Witness::from_slice(&[
            Vec::new(),
            der_signature_with_flag(flag_a),
            der_signature_with_flag(flag_b),
            witness_script.to_bytes(),
        ])
    }

    /// Reads the signature sighash types out of an input spending
    /// `script_pubkey` that has been finalized with the given fields.
    fn final_signature_sighash_types(
        script_pubkey: ScriptBuf,
        final_script_sig: Option<ScriptBuf>,
        final_script_witness: Option<Witness>,
    ) -> Result<Vec<PsbtSighashType>, FinalSignatureError> {
        let txin = TxIn::default();
        let psbtin = psbt::Input {
            witness_utxo: Some(TxOut { value: Amount::from_sat(1_000), script_pubkey }),
            final_script_sig,
            final_script_witness,
            ..Default::default()
        };
        InternalInputPair { txin: &txin, psbtin: &psbtin }.final_signature_sighash_types()
    }

    #[test]
    fn final_signature_sighash_types_p2wsh_multisig() {
        let witness_script = multisig_2_of_2();
        let script_pubkey = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());

        // Both signatures are reported in stack order; the empty dummy and the
        // witnessScript are not.
        assert_eq!(
            final_signature_sighash_types(
                script_pubkey.clone(),
                None,
                Some(multisig_witness(0x01, 0x01, &witness_script)),
            ),
            Ok(vec![EcdsaSighashType::All.into(), EcdsaSighashType::All.into()]),
        );
        assert_eq!(
            final_signature_sighash_types(
                script_pubkey,
                None,
                Some(multisig_witness(0x01, 0x02, &witness_script)),
            ),
            Ok(vec![EcdsaSighashType::All.into(), EcdsaSighashType::None.into()]),
        );
    }

    #[test]
    fn final_signature_sighash_types_p2sh_p2wsh_multisig() {
        let witness_script = multisig_2_of_2();
        let redeem_script = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
        let script_pubkey = ScriptBuf::new_p2sh(&redeem_script.script_hash());
        let script_sig = Builder::new().push_slice(push(redeem_script.as_bytes())).into_script();

        assert_eq!(
            final_signature_sighash_types(
                script_pubkey.clone(),
                Some(script_sig.clone()),
                Some(multisig_witness(0x01, 0x01, &witness_script)),
            ),
            Ok(vec![EcdsaSighashType::All.into(), EcdsaSighashType::All.into()]),
        );
        assert_eq!(
            final_signature_sighash_types(
                script_pubkey,
                Some(script_sig),
                Some(multisig_witness(0x01, 0x02, &witness_script)),
            ),
            Ok(vec![EcdsaSighashType::All.into(), EcdsaSighashType::None.into()]),
        );
    }

    /// A P2TR script path spend of a 2-of-2 CHECKSIG leaf. The witness carries
    /// both Schnorr signatures, the leaf script and a control block with a
    /// one-node merkle path, followed by an annex when one is given.
    ///
    /// The control block is 65 bytes ending in a byte that is not a sighash
    /// type, so scanning it by mistake is an error rather than a silent pass.
    fn taproot_script_path_witness(
        signature_a: &[u8],
        signature_b: &[u8],
        annex: Option<&[u8]>,
    ) -> Witness {
        let leaf_script = Builder::new()
            .push_slice(pubkey(1).x_only_public_key().0.serialize())
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_slice(pubkey(2).x_only_public_key().0.serialize())
            .push_opcode(OP_CHECKSIG)
            .into_script();
        let mut control_block = vec![0xc0];
        control_block.extend_from_slice(&pubkey(3).x_only_public_key().0.serialize());
        control_block.extend_from_slice(&[0xff; 32]);

        let mut elements =
            vec![signature_b.to_vec(), signature_a.to_vec(), leaf_script.to_bytes(), control_block];
        elements.extend(annex.map(<[u8]>::to_vec));
        Witness::from_slice(&elements)
    }

    #[test]
    fn final_signature_sighash_types_p2tr_script_path() {
        let script_pubkey = ScriptBuf::new_p2tr(SECP256K1, pubkey(4).x_only_public_key().0, None);
        let schnorr = [0xab; 64];

        // Both signatures are reported in stack order; the leaf script and
        // control block are not.
        assert_eq!(
            final_signature_sighash_types(
                script_pubkey.clone(),
                None,
                Some(taproot_script_path_witness(&schnorr, &schnorr, None)),
            ),
            Ok(vec![TapSighashType::Default.into(), TapSighashType::Default.into()]),
        );

        let mut signature = schnorr.to_vec();
        signature.push(0x83);
        assert_eq!(
            final_signature_sighash_types(
                script_pubkey,
                None,
                Some(taproot_script_path_witness(&signature, &schnorr, None)),
            ),
            Ok(vec![TapSighashType::Default.into(), TapSighashType::SinglePlusAnyoneCanPay.into()]),
        );
    }

    #[test]
    fn final_signature_sighash_types_p2tr_script_path_annex() {
        let script_pubkey = ScriptBuf::new_p2tr(SECP256K1, pubkey(4).x_only_public_key().0, None);
        let schnorr = [0xab; 64];

        // A 65-byte annex would parse as a Schnorr signature with an invalid
        // sighash byte if it were scanned, so a clean result proves that the
        // annex is excluded.
        let mut annex = vec![0x50; 64];
        annex.push(0xff);
        assert_eq!(
            final_signature_sighash_types(
                script_pubkey.clone(),
                None,
                Some(taproot_script_path_witness(&schnorr, &schnorr, Some(&annex))),
            ),
            Ok(vec![TapSighashType::Default.into(), TapSighashType::Default.into()]),
        );

        let mut signature = schnorr.to_vec();
        signature.push(0x02);
        assert_eq!(
            final_signature_sighash_types(
                script_pubkey,
                None,
                Some(taproot_script_path_witness(&schnorr, &signature, Some(&annex))),
            ),
            Ok(vec![TapSighashType::None.into(), TapSighashType::Default.into()]),
        );
    }

    #[test]
    fn final_signature_sighash_types_bare_p2sh() {
        let redeem_script =
            Builder::new().push_key(&pubkey(1).into()).push_opcode(OP_CHECKSIG).into_script();
        let script_pubkey = ScriptBuf::new_p2sh(&redeem_script.script_hash());
        let script_sig = |flag: u8| {
            Builder::new()
                .push_slice(push(&der_signature_with_flag(flag)))
                .push_slice(push(redeem_script.as_bytes()))
                .into_script()
        };

        // The redeemScript is the last push and is not reported; the signature
        // before it is.
        assert_eq!(
            final_signature_sighash_types(script_pubkey.clone(), Some(script_sig(0x01)), None),
            Ok(vec![EcdsaSighashType::All.into()]),
        );
        assert_eq!(
            final_signature_sighash_types(script_pubkey, Some(script_sig(0x82)), None),
            Ok(vec![EcdsaSighashType::NonePlusAnyoneCanPay.into()]),
        );
    }

    #[test]
    fn final_signature_sighash_types_unfinalized_input() {
        let witness_script = multisig_2_of_2();
        let script_pubkey = ScriptBuf::new_p2wsh(&witness_script.wscript_hash());
        assert_eq!(final_signature_sighash_types(script_pubkey, None, None), Ok(vec![]));
    }
}
