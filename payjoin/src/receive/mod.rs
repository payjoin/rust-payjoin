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

use std::str::FromStr;

use bitcoin::{psbt, AddressType, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut};
pub(crate) use error::InternalPayloadError;
pub use error::{
    Error, InputContributionError, JsonReply, OutputSubstitutionError, PayloadError,
    ReplyableError, SelectionError,
};
use optional_parameters::Params;

pub use crate::psbt::PsbtInputError;
use crate::psbt::{InternalInputPair, InternalPsbtInputError, PrevTxOutError, PsbtExt};
use crate::Version;

mod error;
pub(crate) mod optional_parameters;

#[cfg(feature = "_multiparty")]
pub mod multiparty;
#[cfg(feature = "v1")]
#[cfg_attr(docsrs, doc(cfg(feature = "v1")))]
pub mod v1;
#[cfg(not(feature = "v1"))]
pub(crate) mod v1;

#[cfg(feature = "v2")]
#[cfg_attr(docsrs, doc(cfg(feature = "v2")))]
pub mod v2;

/// Helper to construct a pair of (txin, psbtin) with some built-in validation
/// Use with [`InputPair::new`] to contribute receiver inputs.
#[derive(Clone, Debug)]
pub struct InputPair {
    pub(crate) txin: TxIn,
    pub(crate) psbtin: psbt::Input,
}

impl InputPair {
    pub fn new(txin: TxIn, psbtin: psbt::Input) -> Result<Self, PsbtInputError> {
        let input_pair = Self { txin, psbtin };
        let raw = InternalInputPair::from(&input_pair);
        raw.validate_utxo()?;
        let address_type = raw.address_type().map_err(InternalPsbtInputError::AddressType)?;
        if address_type == AddressType::P2sh && input_pair.psbtin.redeem_script.is_none() {
            return Err(InternalPsbtInputError::NoRedeemScript.into());
        }
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

        let input_pair = Self { txin, psbtin };
        let raw = InternalInputPair::from(&input_pair);
        raw.validate_utxo()?;

        Ok(input_pair)
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

    /// Constructs a new ['InputPair'] for spending a legacy P2PKH output
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

    /// Constructs a new ['InputPair'] for spending a legacy P2SH output
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
        witness_script: Option<ScriptBuf>,
    ) -> Result<Self, PsbtInputError> {
        let txin = TxIn {
            previous_output: OutPoint { txid: outpoint.txid, vout: outpoint.vout },
            script_sig: Default::default(),
            sequence: sequence.unwrap_or_default(),
            witness: Default::default(),
        };

        let psbtin = psbt::Input {
            witness_utxo: Some(TxOut { value: txout.value, script_pubkey: txout.script_pubkey }),
            witness_script,
            ..psbt::Input::default()
        };
        let input_pair = Self { txin, psbtin };
        let raw = InternalInputPair::from(&input_pair);
        raw.validate_utxo()?;

        Ok(input_pair)
    }

    /// Constructs a new ['InputPair'] for spending a native SegWit P2WPKH output
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

    /// Constructs a new ['InputPair'] for spending a native SegWit P2WSH output
    pub fn new_p2wsh(
        txout: TxOut,
        outpoint: OutPoint,
        witness_script: ScriptBuf,
        sequence: Option<Sequence>,
    ) -> Result<Self, PsbtInputError> {
        if !txout.script_pubkey.is_p2wsh() {
            return Err(InternalPsbtInputError::InvalidScriptPubKey(AddressType::P2wsh).into());
        }

        Self::new_segwit_input_pair(txout, outpoint, sequence, Some(witness_script))
    }

    /// Constructs a new ['InputPair'] for spending a native SegWit P2TR output
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
    base64: String,
    query: &str,
    supported_versions: &'static [Version],
) -> Result<(Psbt, Params), PayloadError> {
    let unchecked_psbt = Psbt::from_str(&base64).map_err(InternalPayloadError::ParsePsbt)?;

    let psbt = unchecked_psbt.validate().map_err(InternalPayloadError::InconsistentPsbt)?;
    log::debug!("Received original psbt: {psbt:?}");

    let pairs = url::form_urlencoded::parse(query.as_bytes());
    let params = Params::from_query_pairs(pairs, supported_versions)
        .map_err(InternalPayloadError::SenderParams)?;
    log::debug!("Received request with params: {params:?}");

    Ok((psbt, params))
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::{LockTime, Time};
    use bitcoin::blockdata::script::Builder;
    use bitcoin::hashes::Hash;
    use bitcoin::key::{PublicKey, WPubkeyHash};
    use bitcoin::opcodes::OP_TRUE;
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::{Amount, PubkeyHash, ScriptBuf, ScriptHash, Txid, WScriptHash, XOnlyPublicKey};
    use payjoin_test_utils::{DUMMY20, DUMMY32};

    use super::*;
    use crate::psbt::InternalPsbtInputError::InvalidScriptPubKey;

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
            InputPair::new_p2sh(utxo.clone(), outpoint, redeem_script.clone(), Some(sequence))
                .unwrap();
        assert_eq!(p2sh_pair.txin.previous_output, outpoint);
        assert_eq!(p2sh_pair.txin.sequence, sequence);
        assert_eq!(p2sh_pair.psbtin.redeem_script.unwrap(), redeem_script);
        assert_eq!(p2sh_pair.psbtin.non_witness_utxo.unwrap(), utxo);

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
        let witness_script = Builder::new().push_opcode(OP_TRUE).into_script();
        let p2wsh_pair = InputPair::new_p2wsh(
            p2wsh_txout.clone(),
            outpoint,
            witness_script.clone(),
            Some(sequence),
        )
        .unwrap();
        assert_eq!(p2wsh_pair.txin.previous_output, outpoint);
        assert_eq!(p2wsh_pair.txin.sequence, sequence);
        assert_eq!(p2wsh_pair.psbtin.witness_utxo.unwrap(), p2wsh_txout);
        assert_eq!(p2wsh_pair.psbtin.witness_script.unwrap(), witness_script);

        let p2sh_txout = TxOut {
            value: Default::default(),
            script_pubkey: ScriptBuf::new_p2sh(&ScriptHash::all_zeros()),
        };
        assert_eq!(
            InputPair::new_p2wsh(p2sh_txout, outpoint, witness_script, Some(sequence))
                .err()
                .unwrap(),
            PsbtInputError::from(InvalidScriptPubKey(AddressType::P2wsh))
        )
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

        let p2sh_txout = TxOut {
            value: Default::default(),
            script_pubkey: ScriptBuf::new_p2sh(&ScriptHash::all_zeros()),
        };
        assert_eq!(
            InputPair::new_p2tr(p2sh_txout, outpoint, Some(sequence)).err().unwrap(),
            PsbtInputError::from(InvalidScriptPubKey(AddressType::P2tr))
        )
    }
}
