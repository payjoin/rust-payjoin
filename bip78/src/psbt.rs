//! Utilities to make work with PSBTs easier

use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use bitcoin::{TxIn, TxOut};
use bitcoin::util::psbt;
use std::convert::TryInto;
use std::fmt;

pub(crate) trait PsbtExt {
    type Iterator;

    fn input_pairs(self) -> Self::Iterator;
    fn validate_input_utxos(self, treat_missing_as_error: bool) -> Result<(), PsbtInputsError>;
}

impl<'a> PsbtExt for &'a Psbt {
    type Iterator = std::iter::Map<std::iter::Zip<std::slice::Iter<'a, TxIn>, std::slice::Iter<'a, psbt::Input>>, fn((&'a TxIn, &'a psbt::Input)) -> InputPair<'a>>;

    fn input_pairs(self) -> Self::Iterator {
        assert_eq!(self.global.unsigned_tx.input.len(), self.inputs.len());
        self.global.unsigned_tx.input.iter().zip(&self.inputs).map(|(txin, psbtin)| InputPair { txin, psbtin })
    }

    fn validate_input_utxos(self, treat_missing_as_error: bool) -> Result<(), PsbtInputsError> {
        self
            .input_pairs()
            .enumerate()
            .map(|(index, input)| input.validate_utxo(treat_missing_as_error).map_err(|error| PsbtInputsError { index, error, }))
            .collect()
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
            (Some(tx), None) => {
                tx.output
                    .get::<usize>(self.txin.previous_output.vout.try_into().map_err(|_| PrevTxOutError::IndexOutOfBounds { output_count: tx.output.len(), index: self.txin.previous_output.vout, })?)
                    .ok_or(PrevTxOutError::IndexOutOfBounds { output_count: tx.output.len(), index: self.txin.previous_output.vout, })
            },
        }
    }

    pub fn validate_utxo(&self, treat_missing_as_error: bool) -> Result<(), PsbtInputError> {
        match (&self.psbtin.non_witness_utxo, &self.psbtin.witness_utxo) {
            (None, None) if treat_missing_as_error => Err(PsbtInputError::PrevTxOut(PrevTxOutError::MissingUtxoInformation)),
            (None, None) => Ok(()),
            (Some(tx), None) if tx.txid() == self.txin.previous_output.txid => tx.output
                .get::<usize>(self.txin.previous_output.vout.try_into().map_err(|_| PrevTxOutError::IndexOutOfBounds { output_count: tx.output.len(), index: self.txin.previous_output.vout, })?)
                .ok_or(PrevTxOutError::IndexOutOfBounds { output_count: tx.output.len(), index: self.txin.previous_output.vout, }.into())
                .map(drop),
            (Some(_), None) => Err(PsbtInputError::UnequalTxid),
            (None, Some(_)) => Ok(()),
            (Some(tx), Some(witness_txout)) if tx.txid() == self.txin.previous_output.txid => {
                let non_witness_txout = tx.output
                    .get::<usize>(self.txin.previous_output.vout.try_into().map_err(|_| PrevTxOutError::IndexOutOfBounds { output_count: tx.output.len(), index: self.txin.previous_output.vout, })?)
                    .ok_or(PrevTxOutError::IndexOutOfBounds { output_count: tx.output.len(), index: self.txin.previous_output.vout, })?;
                if witness_txout == non_witness_txout {
                    Ok(())
                } else {
                    Err(PsbtInputError::SegWitTxOutMismatch)
                }
            },
            (Some(_), Some(_)) => Err(PsbtInputError::UnequalTxid),
        }
    }

}

#[derive(Debug)]
pub(crate) enum PrevTxOutError {
    MissingUtxoInformation,
    IndexOutOfBounds { output_count: usize, index: u32, },
}

impl fmt::Display for PrevTxOutError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PrevTxOutError::MissingUtxoInformation => write!(f, "missing UTXO information"),
            PrevTxOutError::IndexOutOfBounds { output_count, index, } => write!(f, "index {} out of bounds (number of outputs: {})", index, output_count),
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
            PsbtInputError::UnequalTxid => write!(f, "transaction ID of previous transaction doesn't match one specified in input spending it"),
            PsbtInputError::SegWitTxOutMismatch => write!(f, "transaction output provided in SegWit UTXO field doesn't match the one in non-SegWit UTXO field"),
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
    fn from(value: PrevTxOutError) -> Self {
        PsbtInputError::PrevTxOut(value)
    }
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
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
