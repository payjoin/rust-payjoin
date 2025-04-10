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

use bitcoin::{psbt, AddressType, OutPoint, Psbt, ScriptBuf, Sequence, TxIn, TxOut, Witness};
pub(crate) use error::InternalPayloadError;
pub use error::{
    Error, ImplementationError, InputContributionError, JsonReply, OutputSubstitutionError,
    PayloadError, ReplyableError, SelectionError,
};
use optional_parameters::Params;

pub use crate::psbt::PsbtInputError;
use crate::psbt::{InternalInputPair, InternalPsbtInputError, PsbtExt};

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

    pub fn new_p2wpkh(
        witness_utxo: TxOut,
        previous_output: OutPoint,
        sequence: Option<Sequence>,
    ) -> Self {
        let txin = TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: sequence.unwrap_or_default(),
            witness: Witness::default(),
        };
        let psbtin = psbt::Input {
            witness_utxo: Some(witness_utxo),
            non_witness_utxo: None,
            redeem_script: None,
            witness_script: None,
            bip32_derivation: Default::default(),
            final_script_sig: None,
            final_script_witness: None,
            ripemd160_preimages: Default::default(),
            sha256_preimages: Default::default(),
            hash160_preimages: Default::default(),
            hash256_preimages: Default::default(),
            tap_key_sig: None,
            tap_script_sigs: Default::default(),
            tap_scripts: Default::default(),
            tap_key_origins: Default::default(),
            tap_internal_key: None,
            tap_merkle_root: None,
            proprietary: Default::default(),
            unknown: Default::default(),
            partial_sigs: Default::default(),
            sighash_type: None,
        };
        Self { txin, psbtin }
    }

    pub fn new_p2tr(
        witness_utxo: TxOut,
        previous_output: OutPoint,
        sequence: Option<Sequence>,
    ) -> Self {
        let txin = TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: sequence.unwrap_or_default(),
            witness: Witness::default(),
        };
        let psbtin = psbt::Input {
            witness_utxo: Some(witness_utxo),
            non_witness_utxo: None,
            redeem_script: None,
            witness_script: None,
            bip32_derivation: Default::default(),
            final_script_sig: None,
            final_script_witness: None,
            ripemd160_preimages: Default::default(),
            sha256_preimages: Default::default(),
            hash160_preimages: Default::default(),
            hash256_preimages: Default::default(),
            tap_key_sig: None,
            tap_script_sigs: Default::default(),
            tap_scripts: Default::default(),
            tap_key_origins: Default::default(),
            tap_internal_key: None,
            tap_merkle_root: None,
            proprietary: Default::default(),
            unknown: Default::default(),
            partial_sigs: Default::default(),
            sighash_type: None,
        };
        Self { txin, psbtin }
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
    supported_versions: &'static [usize],
) -> Result<(Psbt, Params), PayloadError> {
    let unchecked_psbt = Psbt::from_str(&base64).map_err(InternalPayloadError::ParsePsbt)?;

    let psbt = unchecked_psbt.validate().map_err(InternalPayloadError::InconsistentPsbt)?;
    log::debug!("Received original psbt: {:?}", psbt);

    let pairs = url::form_urlencoded::parse(query.as_bytes());
    let params = Params::from_query_pairs(pairs, supported_versions)
        .map_err(InternalPayloadError::SenderParams)?;
    log::debug!("Received request with params: {:?}", params);

    Ok((psbt, params))
}

#[cfg(test)]
mod tests {
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxOut, Txid};

    use super::*; // Import things from the parent module (receive::mod) like InputPair

    #[test]
    fn test_new_p2wpkh_initializes_correctly() {
        // Arrange: Create dummy data
        let dummy_txid =
            Txid::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let dummy_vout = 0;
        let dummy_outpoint = OutPoint { txid: dummy_txid, vout: dummy_vout };
        let dummy_script = ScriptBuf::new(); // A simple empty script for p2wpkh witness_utxo
        let dummy_amount = Amount::from_sat(1000);
        let dummy_txout = TxOut { value: dummy_amount, script_pubkey: dummy_script.clone() };

        // Act: Call the constructor
        let input_pair = InputPair::new_p2wpkh(dummy_txout.clone(), dummy_outpoint, None);

        // Assert: Check the fields of the created InputPair
        // Check psbtin fields
        assert_eq!(input_pair.psbtin.witness_utxo, Some(dummy_txout));
        assert_eq!(input_pair.psbtin.non_witness_utxo, None);
        assert_eq!(input_pair.psbtin.redeem_script, None);
        assert!(input_pair.psbtin.partial_sigs.is_empty());
        assert_eq!(input_pair.psbtin.sighash_type, None);
        assert_eq!(input_pair.psbtin.final_script_sig, None);
        assert_eq!(input_pair.psbtin.final_script_witness, None);
        assert!(input_pair.psbtin.ripemd160_preimages.is_empty());
        assert!(input_pair.psbtin.sha256_preimages.is_empty());
        assert!(input_pair.psbtin.hash160_preimages.is_empty());
        assert_eq!(input_pair.psbtin.tap_key_sig, None);
        assert!(input_pair.psbtin.tap_script_sigs.is_empty());
        assert!(input_pair.psbtin.tap_scripts.is_empty());
        assert!(input_pair.psbtin.proprietary.is_empty());
        assert!(input_pair.psbtin.unknown.is_empty());

        // Check txin field
        assert_eq!(input_pair.txin.previous_output, dummy_outpoint);
        // Other txin fields have defaults we didn't set, less critical to check here
    }

    #[test]
    fn test_new_p2tr_initializes_correctly() {
        // Arrange: Create dummy data (can reuse most logic)
        let dummy_txid =
            Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap(); // Different TXID just for clarity
        let dummy_vout = 1; // Different vout
        let dummy_outpoint = OutPoint { txid: dummy_txid, vout: dummy_vout };
        let dummy_script = ScriptBuf::new();
        let dummy_amount = Amount::from_sat(2000);
        let dummy_txout = TxOut { value: dummy_amount, script_pubkey: dummy_script.clone() };
        let dummy_sequence = Sequence::MAX; // Use the default sequence

        // Act: Call the constructor (using None for sequence to test default)
        let input_pair = InputPair::new_p2tr(dummy_txout.clone(), dummy_outpoint, None);

        // Assert: Check the fields of the created InputPair
        // Check psbtin fields - most should be default/empty
        assert_eq!(input_pair.psbtin.witness_utxo, Some(dummy_txout));
        assert_eq!(input_pair.psbtin.non_witness_utxo, None);
        assert_eq!(input_pair.psbtin.redeem_script, None);
        assert_eq!(input_pair.psbtin.witness_script, None); // P2TR specific
        assert!(input_pair.psbtin.partial_sigs.is_empty());
        assert_eq!(input_pair.psbtin.sighash_type, None);
        assert_eq!(input_pair.psbtin.final_script_sig, None);
        assert_eq!(input_pair.psbtin.final_script_witness, None);
        assert!(input_pair.psbtin.ripemd160_preimages.is_empty());
        assert!(input_pair.psbtin.sha256_preimages.is_empty());
        assert!(input_pair.psbtin.hash160_preimages.is_empty());
        assert!(input_pair.psbtin.hash256_preimages.is_empty()); // P2TR specific check
        assert_eq!(input_pair.psbtin.tap_key_sig, None);
        assert!(input_pair.psbtin.tap_script_sigs.is_empty());
        assert!(input_pair.psbtin.tap_scripts.is_empty());
        assert!(input_pair.psbtin.tap_key_origins.is_empty()); // P2TR specific check
        assert_eq!(input_pair.psbtin.tap_internal_key, None); // P2TR specific check
        assert_eq!(input_pair.psbtin.tap_merkle_root, None); // P2TR specific check
        assert!(input_pair.psbtin.proprietary.is_empty());
        assert!(input_pair.psbtin.unknown.is_empty());

        // Check txin field
        assert_eq!(input_pair.txin.previous_output, dummy_outpoint);
        assert_eq!(input_pair.txin.script_sig, ScriptBuf::new()); // Should be empty for P2TR
        assert_eq!(input_pair.txin.sequence, dummy_sequence); // Check sequence default
        assert!(input_pair.txin.witness.is_empty()); // Witness should be empty initially
    }
}
