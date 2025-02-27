//! Send Payjoin
//!
//! This module contains types and methods used to implement sending via Payjoin.
//!
//! For most use cases, we recommended enabling the `v2` feature, as it is
//! backwards compatible and provides the most convenient experience for users and implementers.
//! To use version 2, refer to `send::v2` module documentation.
//!
//! If you specifically need to use
//! version 1, refer to the `send::v1` module documentation after enabling the `v1` feature.

use std::str::FromStr;

use bitcoin::psbt::Psbt;
use bitcoin::{Amount, FeeRate, Script, ScriptBuf, TxOut, Weight};
pub use error::{BuildSenderError, ResponseError, ValidationError};
pub(crate) use error::{InternalBuildSenderError, InternalProposalError, InternalValidationError};
use url::Url;

use crate::psbt::PsbtExt;

// See usize casts
#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
compile_error!("This crate currently only supports 32 bit and 64 bit architectures");

mod error;

#[cfg(feature = "v1")]
#[cfg_attr(docsrs, doc(cfg(feature = "v1")))]
pub mod v1;
#[cfg(not(feature = "v1"))]
pub(crate) mod v1;

#[cfg(feature = "v2")]
#[cfg_attr(docsrs, doc(cfg(feature = "v2")))]
pub mod v2;

#[cfg(feature = "_multiparty")]
pub mod multiparty;

type InternalResult<T> = Result<T, InternalProposalError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "v2", derive(serde::Serialize, serde::Deserialize))]
pub(crate) struct AdditionalFeeContribution {
    max_amount: Amount,
    vout: usize,
}

/// Data required to validate the response against the original PSBT.
#[derive(Debug, Clone)]
pub struct PsbtContext {
    original_psbt: Psbt,
    disable_output_substitution: bool,
    fee_contribution: Option<AdditionalFeeContribution>,
    min_fee_rate: FeeRate,
    payee: ScriptBuf,
}

macro_rules! check_eq {
    ($proposed:expr, $original:expr, $error:ident) => {
        match ($proposed, $original) {
            (proposed, original) if proposed != original =>
                return Err(InternalProposalError::$error { proposed, original }),
            _ => (),
        }
    };
}

macro_rules! ensure {
    ($cond:expr, $error:ident) => {
        if !($cond) {
            return Err(InternalProposalError::$error);
        }
    };
}

impl PsbtContext {
    fn process_proposal(self, mut proposal: Psbt) -> InternalResult<Psbt> {
        self.basic_checks(&proposal)?;
        self.check_inputs(&proposal)?;
        let contributed_fee = self.check_outputs(&proposal)?;
        self.restore_original_utxos(&mut proposal)?;
        self.check_fees(&proposal, contributed_fee)?;
        Ok(proposal)
    }

    fn check_fees(&self, proposal: &Psbt, contributed_fee: Amount) -> InternalResult<()> {
        let proposed_fee = proposal.fee().map_err(InternalProposalError::Psbt)?;
        let original_fee = self.original_psbt.fee().map_err(InternalProposalError::Psbt)?;
        ensure!(original_fee <= proposed_fee, AbsoluteFeeDecreased);
        ensure!(contributed_fee <= proposed_fee - original_fee, PayeeTookContributedFee);
        let original_weight = self.original_psbt.clone().extract_tx_unchecked_fee_rate().weight();
        let original_fee_rate = original_fee / original_weight;
        let original_spks = self
            .original_psbt
            .input_pairs()
            .map(|input_pair| {
                input_pair
                    .previous_txout()
                    .map_err(InternalProposalError::PrevTxOut)
                    .map(|txout| txout.script_pubkey.clone())
            })
            .collect::<InternalResult<Vec<ScriptBuf>>>()?;
        let additional_input_weight = proposal.input_pairs().try_fold(
            Weight::ZERO,
            |acc, input_pair| -> InternalResult<Weight> {
                let spk = &input_pair
                    .previous_txout()
                    .map_err(InternalProposalError::PrevTxOut)?
                    .script_pubkey;
                if original_spks.contains(spk) {
                    Ok(acc)
                } else {
                    let weight = input_pair
                        .expected_input_weight()
                        .map_err(InternalProposalError::InputWeight)?;
                    Ok(acc + weight)
                }
            },
        )?;
        ensure!(
            contributed_fee <= original_fee_rate * additional_input_weight,
            FeeContributionPaysOutputSizeIncrease
        );
        if self.min_fee_rate > FeeRate::ZERO {
            let proposed_weight = proposal.clone().extract_tx_unchecked_fee_rate().weight();
            ensure!(proposed_fee / proposed_weight >= self.min_fee_rate, FeeRateBelowMinimum);
        }
        Ok(())
    }

    /// Check that the version and lock time are the same as in the original PSBT.
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

    fn check_inputs(&self, proposal: &Psbt) -> InternalResult<()> {
        let mut original_inputs = self.original_psbt.input_pairs().peekable();

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
                        proposed.psbtin.final_script_sig.is_none(),
                        SenderTxinContainsFinalScriptSig
                    );
                    ensure!(
                        proposed.psbtin.final_script_witness.is_none(),
                        SenderTxinContainsFinalScriptWitness
                    );
                    original_inputs.next();
                }
                // theirs (receiver)
                None | Some(_) => {
                    let original = self
                        .original_psbt
                        .input_pairs()
                        .next()
                        .ok_or(InternalProposalError::NoInputs)?;
                    // Verify the PSBT input is finalized
                    ensure!(
                        proposed.psbtin.final_script_sig.is_some()
                            || proposed.psbtin.final_script_witness.is_some(),
                        ReceiverTxinNotFinalized
                    );
                    // Verify that non_witness_utxo or witness_utxo are filled in.
                    ensure!(
                        proposed.psbtin.witness_utxo.is_some()
                            || proposed.psbtin.non_witness_utxo.is_some(),
                        ReceiverTxinMissingUtxoInfo
                    );
                    ensure!(proposed.txin.sequence == original.txin.sequence, MixedSequence);
                }
            }
        }
        ensure!(original_inputs.peek().is_none(), MissingOrShuffledInputs);
        Ok(())
    }

    /// Restore Original PSBT utxos that the receiver stripped.
    /// The BIP78 spec requires utxo information to be removed, but many wallets
    /// require it to be present to sign.
    fn restore_original_utxos(&self, proposal: &mut Psbt) -> InternalResult<()> {
        let mut original_inputs = self.original_psbt.input_pairs().peekable();
        let proposal_inputs =
            proposal.unsigned_tx.input.iter().zip(&mut proposal.inputs).peekable();

        for (proposed_txin, proposed_psbtin) in proposal_inputs {
            if let Some(original) = original_inputs.peek() {
                if proposed_txin.previous_output == original.txin.previous_output {
                    proposed_psbtin.non_witness_utxo = original.psbtin.non_witness_utxo.clone();
                    proposed_psbtin.witness_utxo = original.psbtin.witness_utxo.clone();
                    proposed_psbtin.bip32_derivation = original.psbtin.bip32_derivation.clone();
                    proposed_psbtin.tap_internal_key = original.psbtin.tap_internal_key;
                    proposed_psbtin.tap_key_origins = original.psbtin.tap_key_origins.clone();
                    original_inputs.next();
                }
            }
        }
        Ok(())
    }

    fn check_outputs(&self, proposal: &Psbt) -> InternalResult<Amount> {
        let mut original_outputs =
            self.original_psbt.unsigned_tx.output.iter().enumerate().peekable();
        let mut contributed_fee = Amount::ZERO;

        for (proposed_txout, proposed_psbtout) in
            proposal.unsigned_tx.output.iter().zip(&proposal.outputs)
        {
            ensure!(proposed_psbtout.bip32_derivation.is_empty(), TxOutContainsKeyPaths);
            match (original_outputs.peek(), self.fee_contribution) {
                // fee output
                (
                    Some((original_output_index, original_output)),
                    Some(AdditionalFeeContribution {
                        max_amount: max_fee_contrib,
                        vout: fee_contrib_idx,
                    }),
                ) if proposed_txout.script_pubkey == original_output.script_pubkey
                    && *original_output_index == fee_contrib_idx =>
                {
                    if proposed_txout.value < original_output.value {
                        contributed_fee = original_output.value - proposed_txout.value;
                        ensure!(contributed_fee <= max_fee_contrib, FeeContributionExceedsMaximum);
                        // The remaining fee checks are done in later in `check_fees`
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
                // additional output
                _ => (),
            }
        }

        ensure!(original_outputs.peek().is_none(), MissingOrShuffledOutputs);
        Ok(contributed_fee)
    }
}

/// Ensure that the payee's output scriptPubKey appears in the list of outputs exactly once,
/// and that the payee's output amount matches the requested amount.
fn check_single_payee(
    psbt: &Psbt,
    script_pubkey: &Script,
    amount: Option<bitcoin::Amount>,
) -> Result<(), InternalBuildSenderError> {
    let mut payee_found = false;
    for output in &psbt.unsigned_tx.output {
        if output.script_pubkey == *script_pubkey {
            if let Some(amount) = amount {
                if output.value != amount {
                    return Err(InternalBuildSenderError::PayeeValueNotEqual);
                }
            }
            if payee_found {
                return Err(InternalBuildSenderError::MultiplePayeeOutputs);
            }
            payee_found = true;
        }
    }
    if payee_found {
        Ok(())
    } else {
        Err(InternalBuildSenderError::MissingPayeeOutput)
    }
}

fn clear_unneeded_fields(psbt: &mut Psbt) {
    psbt.xpub_mut().clear();
    psbt.proprietary_mut().clear();
    psbt.unknown_mut().clear();
    for input in psbt.inputs_mut() {
        input.bip32_derivation.clear();
        input.tap_internal_key = None;
        input.tap_key_origins.clear();
        input.tap_key_sig = None;
        input.tap_merkle_root = None;
        input.tap_script_sigs.clear();
        input.proprietary.clear();
        input.unknown.clear();
    }
    for output in psbt.outputs_mut() {
        output.bip32_derivation.clear();
        output.tap_internal_key = None;
        output.tap_key_origins.clear();
        output.proprietary.clear();
        output.unknown.clear();
    }
}

/// Ensure that an additional fee output is sufficient to pay for the specified additional fee
fn check_fee_output_amount(
    output: &TxOut,
    fee: bitcoin::Amount,
    clamp_fee_contribution: bool,
) -> Result<bitcoin::Amount, InternalBuildSenderError> {
    if output.value < fee {
        if clamp_fee_contribution {
            Ok(output.value)
        } else {
            Err(InternalBuildSenderError::FeeOutputValueLowerThanFeeContribution)
        }
    } else {
        Ok(fee)
    }
}

/// Find the sender's change output index by eliminating the payee's output as a candidate.
fn find_change_index(
    psbt: &Psbt,
    payee: &Script,
    fee: bitcoin::Amount,
    clamp_fee_contribution: bool,
) -> Result<Option<AdditionalFeeContribution>, InternalBuildSenderError> {
    match (psbt.unsigned_tx.output.len(), clamp_fee_contribution) {
        (0, _) => return Err(InternalBuildSenderError::NoOutputs),
        (1, false) if psbt.unsigned_tx.output[0].script_pubkey == *payee =>
            return Err(InternalBuildSenderError::FeeOutputValueLowerThanFeeContribution),
        (1, true) if psbt.unsigned_tx.output[0].script_pubkey == *payee => return Ok(None),
        (1, _) => return Err(InternalBuildSenderError::MissingPayeeOutput),
        (2, _) => (),
        _ => return Err(InternalBuildSenderError::AmbiguousChangeOutput),
    }
    let (index, output) = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, output)| output.script_pubkey != *payee)
        .ok_or(InternalBuildSenderError::MultiplePayeeOutputs)?;

    Ok(Some(AdditionalFeeContribution {
        max_amount: check_fee_output_amount(output, fee, clamp_fee_contribution)?,
        vout: index,
    }))
}

/// Check that the change output index is not out of bounds
/// and that the additional fee contribution is not less than specified.
fn check_change_index(
    psbt: &Psbt,
    payee: &Script,
    fee: bitcoin::Amount,
    index: usize,
    clamp_fee_contribution: bool,
) -> Result<AdditionalFeeContribution, InternalBuildSenderError> {
    let output = psbt
        .unsigned_tx
        .output
        .get(index)
        .ok_or(InternalBuildSenderError::ChangeIndexOutOfBounds)?;
    if output.script_pubkey == *payee {
        return Err(InternalBuildSenderError::ChangeIndexPointsAtPayee);
    }
    Ok(AdditionalFeeContribution {
        max_amount: check_fee_output_amount(output, fee, clamp_fee_contribution)?,
        vout: index,
    })
}

fn determine_fee_contribution(
    psbt: &Psbt,
    payee: &Script,
    fee_contribution: Option<(bitcoin::Amount, Option<usize>)>,
    clamp_fee_contribution: bool,
) -> Result<Option<AdditionalFeeContribution>, InternalBuildSenderError> {
    Ok(match fee_contribution {
        Some((fee, None)) => find_change_index(psbt, payee, fee, clamp_fee_contribution)?,
        Some((fee, Some(index))) =>
            Some(check_change_index(psbt, payee, fee, index, clamp_fee_contribution)?),
        None => None,
    })
}

fn serialize_url(
    endpoint: Url,
    disable_output_substitution: bool,
    fee_contribution: Option<AdditionalFeeContribution>,
    min_fee_rate: FeeRate,
    version: &str,
) -> Result<Url, url::ParseError> {
    let mut url = endpoint;
    url.query_pairs_mut().append_pair("v", version);
    if disable_output_substitution {
        url.query_pairs_mut().append_pair("disableoutputsubstitution", "true");
    }
    if let Some(AdditionalFeeContribution { max_amount, vout }) = fee_contribution {
        url.query_pairs_mut()
            .append_pair("additionalfeeoutputindex", &vout.to_string())
            .append_pair("maxadditionalfeecontribution", &max_amount.to_sat().to_string());
    }
    if min_fee_rate > FeeRate::ZERO {
        // TODO serialize in rust-bitcoin <https://github.com/rust-bitcoin/rust-bitcoin/pull/1787/files#diff-c2ea40075e93ccd068673873166cfa3312ec7439d6bc5a4cbc03e972c7e045c4>
        let float_fee_rate = min_fee_rate.to_sat_per_kwu() as f32 / 250.0_f32;
        url.query_pairs_mut().append_pair("minfeerate", &float_fee_rate.to_string());
    }
    Ok(url)
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use bitcoin::hex::FromHex;
    use bitcoin::{Amount, FeeRate, Script, XOnlyPublicKey};
    use payjoin_test_utils::{BoxError, PARSED_ORIGINAL_PSBT, PARSED_PAYJOIN_PROPOSAL};
    use url::Url;

    use super::{
        check_single_payee, clear_unneeded_fields, determine_fee_contribution, serialize_url,
    };
    use crate::psbt::PsbtExt;
    use crate::send::{AdditionalFeeContribution, InternalBuildSenderError, InternalProposalError};

    pub(crate) fn create_psbt_context() -> Result<super::PsbtContext, BoxError> {
        let payee = PARSED_ORIGINAL_PSBT.unsigned_tx.output[1].script_pubkey.clone();
        Ok(super::PsbtContext {
            original_psbt: PARSED_ORIGINAL_PSBT.clone(),
            disable_output_substitution: false,
            fee_contribution: Some(AdditionalFeeContribution {
                max_amount: bitcoin::Amount::from_sat(182),
                vout: 0,
            }),
            min_fee_rate: FeeRate::ZERO,
            payee,
        })
    }

    #[test]
    fn test_determine_fees() -> Result<(), BoxError> {
        let fee_contribution = determine_fee_contribution(
            &PARSED_ORIGINAL_PSBT,
            Script::from_bytes(&<Vec<u8> as FromHex>::from_hex(
                "0014b60943f60c3ee848828bdace7474a92e81f3fcdd",
            )?),
            Some((Amount::from_sat(1000), Some(1))),
            false,
        );
        assert_eq!((*fee_contribution.as_ref().expect("Failed to retrieve fees")).unwrap().vout, 1);
        assert_eq!(
            (*fee_contribution.as_ref().expect("Failed to retrieve fees")).unwrap().max_amount,
            Amount::from_sat(1000)
        );
        Ok(())
    }

    #[test]
    fn test_self_pay_change_index() -> Result<(), BoxError> {
        let script_bytes =
            <Vec<u8> as FromHex>::from_hex("a914774096dbcf486743c22f4347e9b469febe8b677a87")?;
        let payee_script = Script::from_bytes(&script_bytes);
        let fee_contribution = determine_fee_contribution(
            &PARSED_ORIGINAL_PSBT,
            payee_script,
            Some((Amount::from_sat(1000), Some(1))),
            false,
        );
        assert_eq!(
            *payee_script,
            PARSED_ORIGINAL_PSBT
                .unsigned_tx
                .output
                .get(1)
                .ok_or(InternalBuildSenderError::ChangeIndexOutOfBounds)
                .unwrap()
                .script_pubkey
        );
        assert!(fee_contribution.as_ref().is_err(), "determine fee contribution expected Change output points at payee error, but it succeeded");
        match fee_contribution.as_ref() {
            Ok(_) => panic!("Expected error, got success"),
            Err(error) => {
                assert_eq!(*error, InternalBuildSenderError::ChangeIndexPointsAtPayee);
            }
        }
        Ok(())
    }

    #[test]
    fn test_find_change_index() -> Result<(), BoxError> {
        let script_bytes =
            <Vec<u8> as FromHex>::from_hex("0014b60943f60c3ee848828bdace7474a92e81f3fcdd")?;
        let payee_script = Script::from_bytes(&script_bytes);
        let fee_contribution = determine_fee_contribution(
            &PARSED_ORIGINAL_PSBT,
            payee_script,
            Some((Amount::from_sat(1000), None)),
            true,
        );
        assert!(
            fee_contribution.as_ref().is_ok(),
            "Expected an Ok result got: {:#?}",
            fee_contribution.as_ref().err()
        );
        assert_eq!((*fee_contribution.as_ref().expect("Failed to retrieve fees")).unwrap().vout, 0);
        assert_eq!(
            (*fee_contribution.as_ref().expect("Failed to retrieve fees")).unwrap().max_amount,
            Amount::from_sat(1000)
        );
        Ok(())
    }

    #[test]
    fn test_single_payee_amount_mismatch() -> Result<(), BoxError> {
        let script_bytes =
            <Vec<u8> as FromHex>::from_hex("a914774096dbcf486743c22f4347e9b469febe8b677a87")?;
        let payee_script = Script::from_bytes(&script_bytes);
        let single_payee =
            check_single_payee(&PARSED_ORIGINAL_PSBT, payee_script, Some(Amount::from_sat(1)));
        assert!(
            PARSED_ORIGINAL_PSBT
                .unsigned_tx
                .output
                .get(1)
                .ok_or(InternalBuildSenderError::ChangeIndexOutOfBounds)
                .unwrap()
                .script_pubkey
                == *payee_script
        );
        assert!(
            single_payee.is_err(),
            "Check single payee expected payee value not equal error, but it succeeded"
        );
        match single_payee {
            Ok(_) => panic!("Expected error, got success"),
            Err(error) => {
                assert_eq!(error, InternalBuildSenderError::PayeeValueNotEqual);
            }
        }
        Ok(())
    }

    #[test]
    fn test_clear_unneeded_fields() -> Result<(), BoxError> {
        let mut proposal = PARSED_PAYJOIN_PROPOSAL.clone();
        let x_only_key = XOnlyPublicKey::from_str(
            "4f65949efe60e5be80cf171c06144641e832815de4f6ab3fe0257351aeb22a84",
        )?;
        let _ = proposal.inputs[0].tap_internal_key.insert(x_only_key);
        let _ = proposal.outputs[0].tap_internal_key.insert(x_only_key);
        assert!(proposal.inputs[0].tap_internal_key.is_some());
        assert!(!proposal.inputs[0].bip32_derivation.is_empty());
        assert!(proposal.outputs[0].tap_internal_key.is_some());
        assert!(!proposal.outputs[0].bip32_derivation.is_empty());
        clear_unneeded_fields(&mut proposal);
        assert!(proposal.inputs[0].tap_internal_key.is_none());
        assert!(proposal.inputs[0].bip32_derivation.is_empty());
        assert!(proposal.outputs[0].tap_internal_key.is_none());
        assert!(proposal.outputs[0].bip32_derivation.is_empty());
        Ok(())
    }

    #[test]
    fn test_official_vectors() -> Result<(), BoxError> {
        let ctx = create_psbt_context()?;
        let mut proposal = PARSED_PAYJOIN_PROPOSAL.clone();
        for output in proposal.outputs_mut() {
            output.bip32_derivation.clear();
        }
        for input in proposal.inputs_mut() {
            input.bip32_derivation.clear();
        }
        proposal.inputs_mut()[0].witness_utxo = None;
        let result = ctx.process_proposal(proposal.clone());
        assert!(result.is_ok(), "Expected an Ok result got: {:#?}", result.err());
        assert_eq!(
            result.unwrap().inputs_mut()[0].witness_utxo,
            PARSED_ORIGINAL_PSBT.inputs[0].witness_utxo,
        );
        Ok(())
    }

    #[test]
    fn test_receiver_steals_sender_change() -> Result<(), BoxError> {
        let ctx = create_psbt_context()?;
        let mut proposal = PARSED_PAYJOIN_PROPOSAL.clone();
        for output in proposal.outputs_mut() {
            output.bip32_derivation.clear();
        }
        for input in proposal.inputs_mut() {
            input.bip32_derivation.clear();
        }
        proposal.inputs_mut()[0].witness_utxo = None;
        // Steal 0.5 BTC from the sender output and add it to the receiver output
        proposal.unsigned_tx.output[0].value -= bitcoin::Amount::from_btc(0.5)?;
        proposal.unsigned_tx.output[1].value += bitcoin::Amount::from_btc(0.5)?;
        let result = ctx.clone().process_proposal(proposal.clone());
        assert!(
            result.is_err(),
            "Process response expected fee contribution exceeds maximum error, but it succeeded"
        );

        match result {
            Ok(_) => panic!("Expected error, got success"),
            Err(error) => assert_eq!(
                format!("{}", error),
                InternalProposalError::FeeContributionExceedsMaximum.to_string()
            ),
        }
        Ok(())
    }

    #[test]
    fn test_disable_output_substitution_query_param() -> Result<(), BoxError> {
        let url = serialize_url(Url::parse("http://localhost")?, true, None, FeeRate::ZERO, "2")
            .expect("Failed to serialize url");
        assert_eq!(url, Url::parse("http://localhost?v=2&disableoutputsubstitution=true")?);

        let url = serialize_url(Url::parse("http://localhost")?, false, None, FeeRate::ZERO, "2")
            .expect("Failed to serialize url");
        assert_eq!(url, Url::parse("http://localhost?v=2")?);
        Ok(())
    }
}
