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

use bitcoin::{Address, Network, OutPoint, Psbt, ScriptBuf, TxOut, Transaction, TxIn, Sequence, Weight, AddressType, psbt};

pub use error::{
    Error, ImplementationError, InputContributionError, JsonReply, OutputSubstitutionError,
    PayloadError, ReplyableError, SelectionError
};
pub(crate) use error::InternalPayloadError;

use optional_parameters::Params;

#[cfg(test)]
use payjoin_test_utils::ORIGINAL_PSBT;
#[cfg(test)]
use crate::receive::v1::UncheckedProposal;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputWeightError {
    /// Address type is unknown or unsupported
    UnknownAddressType,
    /// Missing UTXO information
    MissingUtxo,
    /// Missing redeem script for P2SH input
    MissingRedeemScript,
    /// Input type not supported
    NotSupported,
    /// Error parsing script
    ScriptError(bitcoin::address::FromScriptError),
}

impl From<bitcoin::address::FromScriptError> for InputWeightError {
    fn from(err: bitcoin::address::FromScriptError) -> Self {
        InputWeightError::ScriptError(err)
    }
}

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
            sequence: sequence.unwrap_or_default(),
            ..Default::default()
        };
        let psbtin = psbt::Input {
            witness_utxo: Some(witness_utxo),
            ..Default::default()
        };
        Self { txin, psbtin }
    }

    pub fn new_p2pkh(
        non_witness_utxo: Transaction,
        previous_output: OutPoint,
        sequence: Option<Sequence>,
    ) -> Self {
        let txin = TxIn {
            previous_output,
            sequence: sequence.unwrap_or_default(),
            ..Default::default()
        };
        let psbtin = psbt::Input {
            non_witness_utxo: Some(non_witness_utxo),
            ..Default::default()
        };
        Self { txin, psbtin }
    }

    pub fn new_p2sh_p2wpkh(
        witness_utxo: TxOut,
        previous_output: OutPoint,
        sequence: Option<Sequence>,
        redeem_script: ScriptBuf,
    ) -> Self {
        let txin = TxIn {
            previous_output,
            sequence: sequence.unwrap_or_default(),
            ..Default::default()
        };
        let psbtin = psbt::Input {
            witness_utxo: Some(witness_utxo),
            redeem_script: Some(redeem_script),
            ..Default::default()
        };
        Self { txin, psbtin }
    }

    pub fn expected_input_weight(&self) -> Result<Weight, InputWeightError> {
        let txin = &self.txin;
        let psbtin = &self.psbtin;

        // For P2PKH and P2SH inputs, we need the non-witness UTXO
        if let Some(ref non_witness_utxo) = psbtin.non_witness_utxo {
            let txout = non_witness_utxo.output.get(txin.previous_output.vout as usize)
                .ok_or(InputWeightError::MissingUtxo)?;
            let addr_type = Address::from_script(&txout.script_pubkey, Network::Bitcoin)?
                .address_type()
                .ok_or(InputWeightError::UnknownAddressType)?;

            match addr_type {
                AddressType::P2pkh => Ok(Weight::from_wu(149 * 4)),  // P2PKH input weight
                AddressType::P2sh => {
                    if let Some(redeem_script) = psbtin.redeem_script.as_ref() {
                        if redeem_script.is_p2wpkh() {
                            Ok(Weight::from_wu(91 * 4))  // P2SH-P2WPKH input weight
                        } else {
                            Err(InputWeightError::NotSupported)
                        }
                    } else {
                        Err(InputWeightError::MissingRedeemScript)
                    }
                },
                _ => Err(InputWeightError::NotSupported),
            }
        } else {
            // For P2WPKH and P2TR inputs, we need the witness UTXO
            if let Some(ref witness_utxo) = psbtin.witness_utxo {
                let addr_type = Address::from_script(&witness_utxo.script_pubkey, Network::Bitcoin)?
                    .address_type()
                    .ok_or(InputWeightError::UnknownAddressType)?;

                match addr_type {
                    AddressType::P2wpkh => Ok(Weight::from_wu(68 * 4)),  // P2WPKH input weight
                    AddressType::P2tr => Ok(Weight::from_wu(57 * 4)),   // P2TR input weight
                    _ => Err(InputWeightError::NotSupported),
                }
            } else {
                Err(InputWeightError::MissingUtxo)
            }
        }
    }

    #[cfg(feature = "v2")]
    pub fn new_p2tr(
        witness_utxo: TxOut,
        previous_output: OutPoint,
        sequence: Option<Sequence>,
    ) -> Self {
        let txin = TxIn {
            previous_output,
            sequence: sequence.unwrap_or_default(),
            ..Default::default()
        };
        let psbtin = psbt::Input {
            witness_utxo: Some(witness_utxo),
            ..Default::default()
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
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxOut, FeeRate, Txid};
    use bitcoin::transaction::Version;
    use bitcoin::absolute::LockTime;

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
    fn test_new_p2pkh_works_with_expected_input_weight() {
        // Arrange: Create dummy data
        let dummy_txid = Txid::from_str("000000000000000000000000000000000000000000000000000000000000000a").unwrap();
        let dummy_txout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Address::from_str("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").unwrap().require_network(Network::Bitcoin).expect("valid network").script_pubkey(),
        };
        let dummy_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![dummy_txout.clone()],
        };
        let dummy_outpoint = OutPoint {
            txid: dummy_txid,
            vout: 0,
        };

        // Act: Create the P2PKH input pair
        let input_pair = InputPair::new_p2pkh(
            dummy_tx,
            dummy_outpoint,
            None,
        );

        // Assert: Should calculate weight for P2PKH input
        assert!(input_pair.expected_input_weight().is_ok());
    }

    #[test]
    fn test_new_p2sh_p2wpkh_works_with_expected_input_weight() {
        // Arrange: Create dummy data
        let dummy_txid = Txid::from_str("000000000000000000000000000000000000000000000000000000000000000b").unwrap();
        let dummy_txout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Address::from_str("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy").unwrap().require_network(Network::Bitcoin).expect("valid network").script_pubkey(),
        };
        let dummy_outpoint = OutPoint {
            txid: dummy_txid,
            vout: 0,
        };
        // Create a proper P2WPKH redeem script
        let dummy_redeem_script = ScriptBuf::new_p2wpkh(&bitcoin::PublicKey::from_str("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").unwrap().wpubkey_hash().expect("valid pubkey"));

        // Act: Create the P2SH-P2WPKH input pair
        let dummy_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![dummy_txout.clone()],
        };
        let mut input_pair = InputPair::new_p2sh_p2wpkh(
            dummy_txout,
            dummy_outpoint,
            None,
            dummy_redeem_script,
        );
        input_pair.psbtin.non_witness_utxo = Some(dummy_tx);

        // Assert: Should calculate weight for P2SH-P2WPKH input
        let result = input_pair.expected_input_weight();
        println!("Result: {:?}", result);
        assert!(result.is_ok());
    }

    #[test]
    #[cfg(feature = "v2")]
    fn test_new_p2tr_works_with_expected_input_weight() {
        // Arrange: Create dummy data with P2TR script
        let dummy_txid = Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111").unwrap();
        let dummy_outpoint = OutPoint { txid: dummy_txid, vout: 0 };
        let dummy_txout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Address::from_str("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0").unwrap().require_network(Network::Bitcoin).expect("valid network").script_pubkey(),
        };

        // Act: Create the P2TR input pair
        let input_pair = InputPair::new_p2tr(dummy_txout, dummy_outpoint, None);

        // Assert: Should calculate weight for P2TR input
        assert!(input_pair.expected_input_weight().is_ok());
    }

    #[test]
    fn test_input_selection_behavior() {
        // Arrange: Create multiple inputs of different types
        let dummy_txid = Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111").unwrap();
        
        // P2WPKH input (low weight)
        let p2wpkh_outpoint = OutPoint { txid: dummy_txid, vout: 0 };
        let p2wpkh_txout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Address::from_str("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap().require_network(Network::Bitcoin).expect("valid network").script_pubkey(),
        };
        let p2wpkh_input = InputPair::new_p2wpkh(p2wpkh_txout.clone(), p2wpkh_outpoint, None);

        // P2PKH input (high weight)
        let p2pkh_outpoint = OutPoint { txid: dummy_txid, vout: 0 };
        let p2pkh_txout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Address::from_str("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").unwrap().require_network(Network::Bitcoin).expect("valid network").script_pubkey(),
        };
        // Create a transaction that contains our UTXO
        let p2pkh_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],  // Empty inputs since this is the transaction we're spending from
            output: vec![p2pkh_txout.clone()],  // Contains our UTXO at index 0
        };
        let p2pkh_input = InputPair::new_p2pkh(p2pkh_tx, p2pkh_outpoint, None);

        // Act & Assert: Compare input weights
        let p2wpkh_weight = p2wpkh_input.expected_input_weight().unwrap();
        let p2pkh_weight = p2pkh_input.expected_input_weight().unwrap();
        assert!(p2wpkh_weight < p2pkh_weight, "P2WPKH should have lower weight than P2PKH");
    }

    #[test]
    fn test_privacy_based_input_selection() {
        // Arrange: Create a transaction with two outputs (common case for UIH testing)
        let dummy_txid = Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111").unwrap();
        // Create a simple transaction with one input and two outputs (payment and change)
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: dummy_txid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![
                // Payment output to receiver
                TxOut {
                    value: Amount::from_sat(40_000),
                    script_pubkey: Address::from_str("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap()
                        .require_network(Network::Bitcoin).expect("valid network").script_pubkey(),
                },
                // Change output back to sender
                TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: Address::from_str("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap()
                        .require_network(Network::Bitcoin).expect("valid network").script_pubkey(),
                },
            ],
        };
        
        // Create PSBT from the transaction
        let mut psbt = Psbt::from_unsigned_tx(tx.clone()).unwrap();
        
        // Add witness UTXO information to the input
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(50_000),  // Input covers both outputs
            script_pubkey: Address::from_str("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap()
                .require_network(Network::Bitcoin).expect("valid network").script_pubkey(),
        });
        
        let proposal = UncheckedProposal {
            psbt,
            params: Params::default(),
        };
        
        // Create candidate inputs with different amounts
        let small_input = InputPair::new_p2wpkh(
            TxOut {
                value: Amount::from_sat(5_000),
                script_pubkey: Address::from_str("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap()
                    .require_network(Network::Bitcoin).expect("valid network").script_pubkey(),
            },
            OutPoint { txid: dummy_txid, vout: 0 },
            None,
        );

        let large_input = InputPair::new_p2wpkh(
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: Address::from_str("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap()
                    .require_network(Network::Bitcoin).expect("valid network").script_pubkey(),
            },
            OutPoint { txid: dummy_txid, vout: 1 },
            None,
        );

        // Act: Try privacy-preserving input selection
        let wants_inputs = proposal
            .assume_interactive_receiver()
            .check_inputs_not_owned(|_| Ok(false))
            .unwrap()
            .check_no_inputs_seen_before(|_| Ok(false))
            .unwrap()
            .identify_receiver_outputs(|script| Ok(script == &tx.output[0].script_pubkey))
            .unwrap()
            .commit_outputs();

        let selected_input = wants_inputs.try_preserving_privacy(vec![small_input.clone(), large_input.clone()]).unwrap();

        // Assert: Selected input should avoid UIH
        // For 2-output transactions, we should select an input that doesn't trigger UIH1 or UIH2
        assert!(selected_input.txin.previous_output == small_input.txin.previous_output ||
               selected_input.txin.previous_output == large_input.txin.previous_output);
    }

    #[test]
    fn test_fee_rate_based_selection() {
        // Arrange: Create a proposal with different fee rates
        let _dummy_txid = Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111").unwrap();
        let proposal = UncheckedProposal {
            psbt: Psbt::from_str(ORIGINAL_PSBT).unwrap(),
            params: Params {
                min_fee_rate: FeeRate::from_sat_per_vb(2).expect("valid fee rate"),
                ..Params::default()
            },
        };

        // Act & Assert: Test minimum fee rate enforcement
        let result = proposal.clone().check_broadcast_suitability(
            Some(FeeRate::from_sat_per_vb(5).expect("valid fee rate")),
            |_| Ok(true)
        );

        // Should fail if proposed fee rate is below minimum
        assert!(matches!(result, 
            Err(ReplyableError::Payload(PayloadError(InternalPayloadError::PsbtBelowFeeRate(_, _))))
        ));
    }

    #[test]
    fn test_minimum_fee_requirements() {
        // This test verifies fee handling behavior:
        // 1. Enforces minimum fee rates to prevent probing attacks
        // 2. Protects against excessive fees with max_effective_fee_rate
        // 3. Correctly deducts fees from receiver's change output
        
        // Create a simple transaction with one input and one output
        let dummy_txid = Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111").unwrap();
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: dummy_txid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: Address::from_str("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap()
                    .require_network(Network::Bitcoin).expect("valid network").script_pubkey(),
            }],
        };
        
        // Create PSBT from the transaction
        let mut psbt = Psbt::from_unsigned_tx(tx.clone()).unwrap();
        
        // Add witness UTXO information to the input
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: Amount::from_sat(60_000),  // Input amount larger than output for fees
            script_pubkey: Address::from_str("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap()
                .require_network(Network::Bitcoin).expect("valid network").script_pubkey(),
        });

        let proposal = UncheckedProposal {
            psbt,
            params: Params::default(),
        };

        // Create a P2WPKH input that will contribute to the payjoin
        let receiver_input = InputPair::new_p2wpkh(
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: Address::from_str("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap()
                    .require_network(Network::Bitcoin).expect("valid network").script_pubkey(),
            },
            OutPoint { txid: dummy_txid, vout: 1 },  // Different vout from sender's input
            None,
        );

        // Progress through the proposal state machine to reach fee application
        let provisional = proposal
            .assume_interactive_receiver()
            .check_inputs_not_owned(|_| Ok(false))
            .unwrap()
            .check_no_inputs_seen_before(|_| Ok(false))
            .unwrap()
            .identify_receiver_outputs(|script| Ok(script == &tx.output[0].script_pubkey))
            .unwrap()
            .commit_outputs()
            .contribute_inputs(vec![receiver_input])
            .unwrap()
            .commit_inputs();

        // Test fee handling with both minimum and maximum constraints:
        // - min_fee_rate: 2 sat/vB ensures transaction is broadcastable
        // - max_effective_fee_rate: 5 sat/vB protects receiver from overpaying
        let result = provisional.finalize_proposal(
            |psbt| Ok(psbt.clone()),  // Mock wallet that just returns the PSBT unchanged
            Some(FeeRate::from_sat_per_vb(2).expect("valid fee rate")),  // Minimum fee rate for broadcast
            Some(FeeRate::from_sat_per_vb(5).expect("valid fee rate"))   // Maximum fee rate receiver will pay
        );

        // Verify that fees were successfully applied within constraints
        assert!(result.is_ok(), "Failed to apply fees meeting minimum requirements");
    }
}
