//! Utilities to make work with PSBTs easier

use std::collections::BTreeMap;
use std::convert::TryInto;
use std::fmt;

use bitcoin::psbt::Psbt;
use bitcoin::{bip32, psbt, TxIn, TxOut};

#[derive(Debug)]
pub(crate) enum InconsistentPsbt {
    UnequalInputCounts { tx_ins: usize, psbt_ins: usize },
    UnequalOutputCounts { tx_outs: usize, psbt_outs: usize },
}

impl fmt::Display for InconsistentPsbt {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InconsistentPsbt::UnequalInputCounts { tx_ins, psbt_ins } =>
                write!(
                    f,
                    "The number of PSBT inputs ({}) doesn't equal to the number of unsigned transaction inputs ({})",
                    psbt_ins,
                    tx_ins
                ),
            InconsistentPsbt::UnequalOutputCounts { tx_outs, psbt_outs } =>
                write!(
                    f,
                    "The number of PSBT outputs ({}) doesn't equal to the number of unsigned transaction outputs ({})",
                    psbt_outs,
                    tx_outs
                ),
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
    ) -> &mut BTreeMap<bip32::ExtendedPubKey, (bip32::Fingerprint, bip32::DerivationPath)>;
    fn proprietary_mut(&mut self) -> &mut BTreeMap<psbt::raw::ProprietaryKey, Vec<u8>>;
    fn unknown_mut(&mut self) -> &mut BTreeMap<psbt::raw::Key, Vec<u8>>;
    fn input_pairs(&self) -> Box<dyn Iterator<Item = InputPair<'_>> + '_>;
    // guarantees that length of psbt input matches that of unsigned_tx inputs and same
    /// thing for outputs.
    fn validate(self) -> Result<Self, InconsistentPsbt>;
    fn validate_input_utxos(&self, treat_missing_as_error: bool) -> Result<(), PsbtInputsError>;
    fn calculate_fee(&self) -> bitcoin::Amount;
}

impl PsbtExt for Psbt {
    fn inputs_mut(&mut self) -> &mut [psbt::Input] { &mut self.inputs }

    fn outputs_mut(&mut self) -> &mut [psbt::Output] { &mut self.outputs }

    fn xpub_mut(
        &mut self,
    ) -> &mut BTreeMap<bip32::ExtendedPubKey, (bip32::Fingerprint, bip32::DerivationPath)> {
        &mut self.xpub
    }

    fn proprietary_mut(&mut self) -> &mut BTreeMap<psbt::raw::ProprietaryKey, Vec<u8>> {
        &mut self.proprietary
    }

    fn unknown_mut(&mut self) -> &mut BTreeMap<psbt::raw::Key, Vec<u8>> { &mut self.unknown }

    fn input_pairs(&self) -> Box<dyn Iterator<Item = InputPair<'_>> + '_> {
        Box::new(
            self.unsigned_tx
                .input
                .iter()
                .zip(&self.inputs)
                .map(|(txin, psbtin)| InputPair { txin, psbtin }),
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

    fn validate_input_utxos(&self, treat_missing_as_error: bool) -> Result<(), PsbtInputsError> {
        self.input_pairs().enumerate().try_for_each(|(index, input)| {
            input
                .validate_utxo(treat_missing_as_error)
                .map_err(|error| PsbtInputsError { index, error })
        })
    }

    fn calculate_fee(&self) -> bitcoin::Amount {
        let mut total_outputs = bitcoin::Amount::ZERO;
        let mut total_inputs = bitcoin::Amount::ZERO;

        for output in &self.unsigned_tx.output {
            total_outputs += bitcoin::Amount::from_sat(output.value);
        }

        for input in self.input_pairs() {
            total_inputs += bitcoin::Amount::from_sat(input.previous_txout().unwrap().value);
        }
        log::debug!("  total_inputs:  {}", total_inputs);
        log::debug!("- total_outputs: {}", total_outputs);
        total_inputs - total_outputs
    }
}

pub(crate) struct InputPair<'a> {
    pub txin: &'a TxIn,
    pub psbtin: &'a psbt::Input,
}

impl<'a> InputPair<'a> {
    /// Returns TxOut associated with the input
    pub fn previous_txout(&self) -> Result<&TxOut, PrevTxOutError> {
        match (&self.psbtin.non_witness_utxo, &self.psbtin.witness_utxo) {
            (None, None) => Err(PrevTxOutError::MissingUtxoInformation),
            (_, Some(txout)) => Ok(txout),
            (Some(tx), None) => tx
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
                }),
        }
    }

    pub fn validate_utxo(&self, treat_missing_as_error: bool) -> Result<(), PsbtInputError> {
        match (&self.psbtin.non_witness_utxo, &self.psbtin.witness_utxo) {
            (None, None) if treat_missing_as_error =>
                Err(PsbtInputError::PrevTxOut(PrevTxOutError::MissingUtxoInformation)),
            (None, None) => Ok(()),
            (Some(tx), None) if tx.txid() == self.txin.previous_output.txid => tx
                .output
                .get::<usize>(self.txin.previous_output.vout.try_into().map_err(|_| {
                    PrevTxOutError::IndexOutOfBounds {
                        output_count: tx.output.len(),
                        index: self.txin.previous_output.vout,
                    }
                })?)
                .ok_or_else(|| {
                    (PrevTxOutError::IndexOutOfBounds {
                        output_count: tx.output.len(),
                        index: self.txin.previous_output.vout,
                    })
                    .into()
                })
                .map(drop),
            (Some(_), None) => Err(PsbtInputError::UnequalTxid),
            (None, Some(_)) => Ok(()),
            (Some(tx), Some(witness_txout)) if tx.txid() == self.txin.previous_output.txid => {
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
                    Err(PsbtInputError::SegWitTxOutMismatch)
                }
            }
            (Some(_), Some(_)) => Err(PsbtInputError::UnequalTxid),
        }
    }
}

#[derive(Debug)]
pub(crate) enum PrevTxOutError {
    MissingUtxoInformation,
    IndexOutOfBounds { output_count: usize, index: u32 },
}

impl fmt::Display for PrevTxOutError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PrevTxOutError::MissingUtxoInformation => write!(f, "missing UTXO information"),
            PrevTxOutError::IndexOutOfBounds { output_count, index } => {
                write!(f, "index {} out of bounds (number of outputs: {})", index, output_count)
            }
        }
    }
}

impl std::error::Error for PrevTxOutError {}

#[derive(Debug)]
pub(crate) enum PsbtInputError {
    PrevTxOut(PrevTxOutError),
    UnequalTxid,
    /// TxOut provided in `segwit_utxo` doesn't match the one in `non_segwit_utxo`
    SegWitTxOutMismatch,
}

impl fmt::Display for PsbtInputError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PsbtInputError::PrevTxOut(_) => write!(f, "invalid previous transaction output"),
            PsbtInputError::UnequalTxid =>
                write!(
                    f,
                    "transaction ID of previous transaction doesn't match one specified in input spending it"
                ),
            PsbtInputError::SegWitTxOutMismatch =>
                write!(
                    f,
                    "transaction output provided in SegWit UTXO field doesn't match the one in non-SegWit UTXO field"
                ),
        }
    }
}

impl std::error::Error for PsbtInputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PsbtInputError::PrevTxOut(error) => Some(error),
            PsbtInputError::UnequalTxid => None,
            PsbtInputError::SegWitTxOutMismatch => None,
        }
    }
}

impl From<PrevTxOutError> for PsbtInputError {
    fn from(value: PrevTxOutError) -> Self { PsbtInputError::PrevTxOut(value) }
}

#[derive(Debug)]
pub struct PsbtInputsError {
    index: usize,
    error: PsbtInputError,
}

impl fmt::Display for PsbtInputsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid PSBT input #{}", self.index)
    }
}

impl std::error::Error for PsbtInputsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.error) }
}
