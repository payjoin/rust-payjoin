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
pub use error::{BuildSenderError, ResponseError, ValidationError, WellKnownError};
pub(crate) use error::{InternalBuildSenderError, InternalProposalError, InternalValidationError};
use url::Url;

use crate::output_substitution::OutputSubstitution;
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
#[cfg(all(feature = "v2", not(feature = "v1")))]
pub use v1::V1Context;

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
    output_substitution: OutputSubstitution,
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

fn ensure<T>(condition: bool, error: T) -> Result<(), T> {
    if !condition {
        return Err(error);
    }
    Ok(())
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
        ensure(original_fee <= proposed_fee, InternalProposalError::AbsoluteFeeDecreased)?;
        ensure(
            contributed_fee <= proposed_fee - original_fee,
            InternalProposalError::PayeeTookContributedFee,
        )?;
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
        ensure(
            contributed_fee <= original_fee_rate * additional_input_weight,
            InternalProposalError::FeeContributionPaysOutputSizeIncrease,
        )?;
        if self.min_fee_rate > FeeRate::ZERO {
            let proposed_weight = proposal.clone().extract_tx_unchecked_fee_rate().weight();
            ensure(
                proposed_fee / proposed_weight >= self.min_fee_rate,
                InternalProposalError::FeeRateBelowMinimum,
            )?;
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
            ensure(
                proposed.pair.psbtin.bip32_derivation.is_empty(),
                InternalProposalError::TxInContainsKeyPaths,
            )?;
            ensure(
                proposed.pair.psbtin.partial_sigs.is_empty(),
                InternalProposalError::ContainsPartialSigs,
            )?;
            match original_inputs.peek() {
                // our (sender)
                Some(original)
                    if proposed.pair.txin.previous_output == original.pair.txin.previous_output =>
                {
                    check_eq!(
                        proposed.pair.txin.sequence,
                        original.pair.txin.sequence,
                        SenderTxinSequenceChanged
                    );
                    ensure(
                        proposed.pair.psbtin.final_script_sig.is_none(),
                        InternalProposalError::SenderTxinContainsFinalScriptSig,
                    )?;
                    ensure(
                        proposed.pair.psbtin.final_script_witness.is_none(),
                        InternalProposalError::SenderTxinContainsFinalScriptWitness,
                    )?;
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
                    ensure(
                        proposed.pair.psbtin.final_script_sig.is_some()
                            || proposed.pair.psbtin.final_script_witness.is_some(),
                        InternalProposalError::ReceiverTxinNotFinalized,
                    )?;
                    // Verify that non_witness_utxo or witness_utxo are filled in.
                    ensure(
                        proposed.pair.psbtin.witness_utxo.is_some()
                            || proposed.pair.psbtin.non_witness_utxo.is_some(),
                        InternalProposalError::ReceiverTxinMissingUtxoInfo,
                    )?;
                    ensure(
                        proposed.pair.txin.sequence == original.pair.txin.sequence,
                        InternalProposalError::MixedSequence,
                    )?;
                }
            }
        }
        ensure(original_inputs.peek().is_none(), InternalProposalError::MissingOrShuffledInputs)?;
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
                if proposed_txin.previous_output == original.pair.txin.previous_output {
                    proposed_psbtin.non_witness_utxo =
                        original.pair.psbtin.non_witness_utxo.clone();
                    proposed_psbtin.witness_utxo = original.pair.psbtin.witness_utxo.clone();
                    proposed_psbtin.bip32_derivation =
                        original.pair.psbtin.bip32_derivation.clone();
                    proposed_psbtin.tap_internal_key = original.pair.psbtin.tap_internal_key;
                    proposed_psbtin.tap_key_origins = original.pair.psbtin.tap_key_origins.clone();
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
            ensure(
                proposed_psbtout.bip32_derivation.is_empty(),
                InternalProposalError::TxOutContainsKeyPaths,
            )?;
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
                        ensure(
                            contributed_fee <= max_fee_contrib,
                            InternalProposalError::FeeContributionExceedsMaximum,
                        )?;
                        // The remaining fee checks are done in later in `check_fees`
                    }
                    original_outputs.next();
                }
                // payee output
                (Some((_original_output_index, original_output)), _)
                    if original_output.script_pubkey == self.payee =>
                {
                    ensure(
                        self.output_substitution == OutputSubstitution::Enabled
                            || (proposed_txout.script_pubkey == original_output.script_pubkey
                                && proposed_txout.value >= original_output.value),
                        InternalProposalError::DisallowedOutputSubstitution,
                    )?;
                    original_outputs.next();
                }
                // our output
                (Some((_original_output_index, original_output)), _)
                    if proposed_txout.script_pubkey == original_output.script_pubkey =>
                {
                    ensure(
                        proposed_txout.value >= original_output.value,
                        InternalProposalError::OutputValueDecreased,
                    )?;
                    original_outputs.next();
                }
                // additional output
                _ => (),
            }
        }

        ensure(original_outputs.peek().is_none(), InternalProposalError::MissingOrShuffledOutputs)?;
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
    output_substitution: OutputSubstitution,
    fee_contribution: Option<AdditionalFeeContribution>,
    min_fee_rate: FeeRate,
    version: &str,
) -> Url {
    let mut url = endpoint;
    url.query_pairs_mut().append_pair("v", version);
    if output_substitution == OutputSubstitution::Disabled {
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
    url
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use bitcoin::absolute::LockTime;
    use bitcoin::ecdsa::Signature;
    use bitcoin::hex::FromHex;
    use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, FeeRate, OutPoint, Script, ScriptBuf, Sequence, Witness, XOnlyPublicKey,
    };
    use payjoin_test_utils::{
        BoxError, PARSED_ORIGINAL_PSBT, PARSED_PAYJOIN_PROPOSAL,
        PARSED_PAYJOIN_PROPOSAL_WITH_SENDER_INFO,
    };
    use url::Url;

    use super::{
        check_single_payee, clear_unneeded_fields, determine_fee_contribution, serialize_url,
    };
    use crate::output_substitution::OutputSubstitution;
    use crate::psbt::PsbtExt;
    use crate::send::{AdditionalFeeContribution, InternalBuildSenderError, InternalProposalError};

    /// Creates a PSBT context from the original PSBT test vector from BIP-78
    pub(crate) fn create_psbt_context() -> Result<super::PsbtContext, BoxError> {
        let payee = PARSED_ORIGINAL_PSBT.unsigned_tx.output[1].script_pubkey.clone();
        Ok(super::PsbtContext {
            original_psbt: PARSED_ORIGINAL_PSBT.clone(),
            output_substitution: OutputSubstitution::Enabled,
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
    fn test_insufficient_fees() -> Result<(), BoxError> {
        let fee_contribution = determine_fee_contribution(
            &PARSED_ORIGINAL_PSBT,
            Script::from_bytes(&<Vec<u8> as FromHex>::from_hex(
                "0014b60943f60c3ee848828bdace7474a92e81f3fcdd",
            )?),
            Some((Amount::from_sat(100000000), None)),
            false,
        );
        assert_eq!(
            fee_contribution.err(),
            Some(InternalBuildSenderError::FeeOutputValueLowerThanFeeContribution)
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
        // All psbt vectors are modifications on the original psbt from bip78
        // Starts with the unmodified original psbt
        let mut psbt = PARSED_ORIGINAL_PSBT.clone();
        let payee_script = ScriptBuf::from_hex("0014b60943f60c3ee848828bdace7474a92e81f3fcdd")?;
        let fee_contribution = determine_fee_contribution(
            &psbt,
            &payee_script,
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

        // Psbt with zero outputs
        psbt.outputs.clear();
        psbt.unsigned_tx.output.clear();

        let fee_contribution = determine_fee_contribution(
            &psbt,
            &ScriptBuf::from_hex("0014908eb2d695cf78e39a621d1561655790d1a8c60f")?,
            Some((Amount::from_sat(1000), None)),
            true,
        );
        assert_eq!(fee_contribution, Err(InternalBuildSenderError::NoOutputs));

        // Psbt with identical receiver outputs
        let mut psbt = PARSED_ORIGINAL_PSBT.clone();
        psbt.outputs[1] = psbt.outputs[0].clone();
        psbt.unsigned_tx.output[1].script_pubkey = psbt.unsigned_tx.output[0].script_pubkey.clone();

        let fee_contribution = determine_fee_contribution(
            &psbt,
            &ScriptBuf::from_hex("a9141de849f069d274150e3afeae8d72eb5a6b09443087")?,
            Some((Amount::from_sat(1000), None)),
            true,
        );
        assert_eq!(fee_contribution, Err(InternalBuildSenderError::MultiplePayeeOutputs));

        // Psbt with only one output
        let mut psbt = PARSED_ORIGINAL_PSBT.clone();
        psbt.outputs.pop();
        psbt.unsigned_tx.output.pop();

        let fee_contribution = determine_fee_contribution(
            &psbt,
            Script::from_bytes(
                &<Vec<u8> as FromHex>::from_hex("a9141de849f069d274150e3afeae8d72eb5a6b09443087")
                    .unwrap(),
            ),
            Some((Amount::from_sat(1000), None)),
            true,
        );
        assert_eq!(fee_contribution, Ok(None));

        let fee_contribution = determine_fee_contribution(
            &psbt,
            Script::from_bytes(
                &<Vec<u8> as FromHex>::from_hex("a9141de849f069d274150e3afeae8d72eb5a6b09443087")
                    .unwrap(),
            ),
            Some((Amount::from_sat(1000), None)),
            false,
        );
        assert_eq!(
            fee_contribution,
            Err(InternalBuildSenderError::FeeOutputValueLowerThanFeeContribution)
        );

        let fee_contribution = determine_fee_contribution(
            &psbt,
            &payee_script,
            Some((Amount::from_sat(1000), None)),
            false,
        );
        assert_eq!(fee_contribution, Err(InternalBuildSenderError::MissingPayeeOutput));

        let fee_contribution = determine_fee_contribution(
            &psbt,
            &payee_script,
            Some((Amount::from_sat(1000), None)),
            true,
        );
        assert_eq!(fee_contribution, Err(InternalBuildSenderError::MissingPayeeOutput));

        // Psbt with three total outputs
        let mut psbt = PARSED_ORIGINAL_PSBT.clone();
        psbt.outputs.push(psbt.outputs[1].clone());
        psbt.unsigned_tx.output.push(psbt.unsigned_tx.output[1].clone());

        let fee_contribution = determine_fee_contribution(
            &psbt,
            &payee_script,
            Some((Amount::from_sat(1000), None)),
            true,
        );
        assert_eq!(fee_contribution, Err(InternalBuildSenderError::AmbiguousChangeOutput));
        Ok(())
    }

    #[test]
    fn test_single_payee_amount_mismatch() -> Result<(), BoxError> {
        let payee_script = ScriptBuf::from_hex("a914774096dbcf486743c22f4347e9b469febe8b677a87")?;
        let single_payee =
            check_single_payee(&PARSED_ORIGINAL_PSBT, &payee_script, Some(Amount::from_sat(1)));
        assert!(
            PARSED_ORIGINAL_PSBT
                .unsigned_tx
                .output
                .get(1)
                .ok_or(InternalBuildSenderError::ChangeIndexOutOfBounds)
                .unwrap()
                .script_pubkey
                == payee_script
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
    fn test_equal_amount_fee_contribution() -> Result<(), BoxError> {
        let mut ctx = create_psbt_context()?;
        let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

        ctx.fee_contribution = None;
        proposal.unsigned_tx.output[0].value = ctx.original_psbt.unsigned_tx.output[0].value;

        assert!(ctx.process_proposal(proposal).is_ok());

        Ok(())
    }

    #[test]
    fn test_payee_output_value_decreased() -> Result<(), BoxError> {
        let mut ctx = create_psbt_context()?;
        let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

        ctx.fee_contribution = None;
        proposal.unsigned_tx.output[0].value =
            ctx.original_psbt.unsigned_tx.output[0].value - Amount::from_sat(1);

        ctx.original_psbt.unsigned_tx.output[0].script_pubkey =
            ctx.original_psbt.unsigned_tx.output[1].script_pubkey.clone();
        assert!(ctx.clone().process_proposal(proposal.clone()).is_ok());

        ctx.original_psbt.unsigned_tx.output[0].script_pubkey = ctx.payee.clone();
        assert!(ctx.process_proposal(proposal).is_ok());

        Ok(())
    }

    #[test]
    fn test_clear_unneeded_fields() -> Result<(), BoxError> {
        let mut proposal = PARSED_PAYJOIN_PROPOSAL_WITH_SENDER_INFO.clone();
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
        let mut proposal = PARSED_PAYJOIN_PROPOSAL_WITH_SENDER_INFO.clone();
        for output in proposal.outputs_mut() {
            output.bip32_derivation.clear();
        }
        for input in proposal.inputs_mut() {
            input.bip32_derivation.clear();
        }
        proposal.inputs_mut()[0].witness_utxo = None;
        let result = ctx.process_proposal(proposal);
        assert!(result.is_ok(), "Expected an Ok result got: {:#?}", result.err());
        assert_eq!(
            result.unwrap().inputs_mut()[0].witness_utxo,
            PARSED_ORIGINAL_PSBT.inputs[0].witness_utxo,
        );
        Ok(())
    }

    #[test]
    fn test_disable_output_substitution_query_param() -> Result<(), BoxError> {
        let url = serialize_url(
            Url::parse("http://localhost")?,
            OutputSubstitution::Disabled,
            None,
            FeeRate::ZERO,
            "2",
        );
        assert_eq!(url, Url::parse("http://localhost?v=2&disableoutputsubstitution=true")?);

        let url = serialize_url(
            Url::parse("http://localhost")?,
            OutputSubstitution::Enabled,
            None,
            FeeRate::ZERO,
            "2",
        );
        assert_eq!(url, Url::parse("http://localhost?v=2")?);
        Ok(())
    }

    #[test]
    fn test_min_feerate_query_param() -> Result<(), BoxError> {
        let url = serialize_url(
            Url::parse("http://localhost")?,
            OutputSubstitution::Enabled,
            None,
            FeeRate::from_sat_per_vb(10).expect("Could not parse feerate"),
            "2",
        );
        assert_eq!(url, Url::parse("http://localhost?v=2&minfeerate=10")?);
        Ok(())
    }

    #[test]
    fn test_additional_fee_contribution_query_param() -> Result<(), BoxError> {
        let url = serialize_url(
            Url::parse("http://localhost")?,
            OutputSubstitution::Enabled,
            Some(AdditionalFeeContribution { max_amount: Amount::from_sat(1000), vout: 0 }),
            FeeRate::ZERO,
            "2",
        );
        assert_eq!(
            url,
            Url::parse(
                "http://localhost?v=2&additionalfeeoutputindex=0&maxadditionalfeecontribution=1000"
            )?
        );
        Ok(())
    }

    /// Test the sender's payjoin proposal checklist
    /// See: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#user-content-Senders_payjoin_proposal_checklist
    mod bip78_checklist {
        use super::*;

        #[test]
        fn test_transaction_versions_dont_match() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            let original_version = ctx.original_psbt.unsigned_tx.version;
            let proposed_version = Version::non_standard(88);
            proposal.unsigned_tx.version = proposed_version;

            assert!(matches!(
                ctx.process_proposal(proposal),
                Err(InternalProposalError::VersionsDontMatch {
                    proposed,
                    original
                }) if proposed == proposed_version && original == original_version
            ));
            Ok(())
        }

        #[test]
        fn test_transaction_locktimes_dont_match() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            let original_locktime = ctx.original_psbt.unsigned_tx.lock_time;
            let proposed_locktime = LockTime::from_consensus(
                ctx.original_psbt.unsigned_tx.lock_time.to_consensus_u32() - 1,
            );
            proposal.unsigned_tx.lock_time = proposed_locktime;

            assert!(matches!(
                ctx.process_proposal(proposal),
                Err(InternalProposalError::LockTimesDontMatch {
                    proposed,
                    original
                }) if proposed == proposed_locktime && original == original_locktime
            ));
            Ok(())
        }

        #[test]
        fn test_key_path_found_in_proposal() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            // Add a keypath to the input
            let context = Secp256k1::new();
            let secret_key =
                SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
            proposal.inputs[0].bip32_derivation.insert(
                PublicKey::from_secret_key(&context, &secret_key),
                bitcoin::bip32::KeySource::default(),
            );

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::TxInContainsKeyPaths.to_string()
            );
            Ok(())
        }

        #[test]
        fn test_partial_sig_found_in_proposal() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            // Add a keypath to the input
            let context = Secp256k1::new();
            let secret_key =
                SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
            proposal.inputs[0].partial_sigs.insert(
                PublicKey::from_secret_key(&context, &secret_key).into(),
                Signature::sighash_all(secret_key.sign_ecdsa(Message::from_digest([0; 32]))),
            );

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::ContainsPartialSigs.to_string()
            );
            Ok(())
        }

        #[test]
        fn test_sender_input_sequence_number_changed() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            // Change the sequence number of the proposal
            let original_sequence = proposal.unsigned_tx.input.first().unwrap().sequence;
            let proposed_sequence =
                Sequence::from_consensus(original_sequence.to_consensus_u32() - 1);
            proposal.unsigned_tx.input.get_mut(0).unwrap().sequence = proposed_sequence;

            assert!(matches!(
                ctx.process_proposal(proposal),
                Err(InternalProposalError::SenderTxinSequenceChanged {
                    proposed,
                    original
                }) if proposed == proposed_sequence && original == original_sequence
            ));
            Ok(())
        }

        #[test]
        fn test_sender_input_final_script_sig_is_present() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();
            proposal.inputs.get_mut(0).unwrap().final_script_sig = Some(ScriptBuf::new());

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::SenderTxinContainsFinalScriptSig.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_sender_input_final_script_witness_is_present() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();
            proposal.inputs.get_mut(0).unwrap().final_script_witness = Some(Witness::new());

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::SenderTxinContainsFinalScriptWitness.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_receiver_input_is_not_finalized() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            // If the outpoints are different, they are considered a receiver input and will be checked as such
            let proposed_outpoint = proposal.unsigned_tx.input.first().unwrap().previous_output;
            proposal.unsigned_tx.input.get_mut(0).unwrap().previous_output =
                OutPoint::new(proposed_outpoint.txid, proposed_outpoint.vout + 1);

            // Make the receiver's input un-finalized
            proposal.inputs.get_mut(0).unwrap().final_script_sig = None;
            proposal.inputs.get_mut(0).unwrap().final_script_witness = None;

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::ReceiverTxinNotFinalized.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_receiver_input_missing_witness_info() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            // If the outpoints are different, they are considered a receiver input and will be checked as such
            let proposed_outpoint = proposal.unsigned_tx.input.first().unwrap().previous_output;
            proposal.unsigned_tx.input.get_mut(0).unwrap().previous_output =
                OutPoint::new(proposed_outpoint.txid, proposed_outpoint.vout + 1);
            proposal.inputs.get_mut(0).unwrap().final_script_sig = Some(ScriptBuf::new());
            proposal.inputs.get_mut(0).unwrap().final_script_witness = Some(Witness::new());

            // Make the receiver's input un-finalized
            proposal.inputs.get_mut(0).unwrap().witness_utxo = None;
            proposal.inputs.get_mut(0).unwrap().non_witness_utxo = None;

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::ReceiverTxinMissingUtxoInfo.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_receiver_input_has_mixed_sequence_() -> Result<(), BoxError> {
            let mut ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            // If the outpoints are different, they are considered a receiver input and will be checked as such
            let proposed_outpoint = proposal.unsigned_tx.input.first().unwrap().previous_output;
            proposal.unsigned_tx.input.get_mut(0).unwrap().previous_output =
                OutPoint::new(proposed_outpoint.txid, proposed_outpoint.vout + 1);
            proposal.inputs.get_mut(0).unwrap().final_script_sig = Some(ScriptBuf::new());
            proposal.inputs.get_mut(0).unwrap().final_script_witness = Some(Witness::new());

            // Ensure the sequence is different
            let sequence = ctx.original_psbt.unsigned_tx.input.get_mut(0).unwrap().sequence;
            proposal.unsigned_tx.input.get_mut(0).unwrap().sequence =
                Sequence::from_consensus(sequence.to_consensus_u32() + 1);

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::MixedSequence.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_process_proposal_when_missing_original_inputs() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            proposal.unsigned_tx.input.clear();
            proposal.inputs.clear();

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::MissingOrShuffledInputs.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_process_proposal_when_output_contains_key_path() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            let context = Secp256k1::new();
            let secret_key =
                SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
            proposal.outputs.get_mut(0).unwrap().bip32_derivation.insert(
                PublicKey::from_secret_key(&context, &secret_key),
                bitcoin::bip32::KeySource::default(),
            );

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::TxOutContainsKeyPaths.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_receiver_steals_sender_change() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal = PARSED_PAYJOIN_PROPOSAL.clone();
            // Steal 0.5 BTC from the sender output and add it to the receiver output
            proposal.unsigned_tx.output[0].value -= Amount::from_btc(0.5)?;
            proposal.unsigned_tx.output[1].value += Amount::from_btc(0.5)?;

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::FeeContributionExceedsMaximum.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_process_proposal_when_payee_output_has_disallowed_output_substitution(
        ) -> Result<(), BoxError> {
            let mut ctx = create_psbt_context()?;
            let mut proposal = PARSED_PAYJOIN_PROPOSAL.clone();
            ctx.output_substitution = OutputSubstitution::Disabled;

            // When output substitution is disabled ensure that the output value did not decrease
            assert!(ctx.clone().process_proposal(proposal.clone()).is_ok());

            // When output substitution is disabled still allow increasing the output value
            proposal.unsigned_tx.output[0].value += Amount::from_sat(182);
            assert!(ctx.clone().process_proposal(proposal.clone()).is_ok());

            proposal.unsigned_tx.output[0].value -= Amount::from_sat(182);
            ctx.original_psbt.unsigned_tx.output.get_mut(0).unwrap().script_pubkey =
                ctx.payee.clone();
            std::mem::swap(
                &mut ctx.original_psbt.unsigned_tx.output[0].value,
                &mut proposal.unsigned_tx.output[0].value,
            );
            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::DisallowedOutputSubstitution.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_process_proposal_when_payee_output_has_allowed_output_substitution(
        ) -> Result<(), BoxError> {
            let mut ctx = create_psbt_context()?;
            let mut proposal = PARSED_PAYJOIN_PROPOSAL.clone();

            // Do not make any checks when output substitution is enabled
            ctx.output_substitution = OutputSubstitution::Enabled;
            ctx.original_psbt.unsigned_tx.output.get_mut(0).unwrap().script_pubkey =
                ctx.payee.clone();
            assert!(ctx.clone().process_proposal(proposal.clone()).is_ok());

            proposal.unsigned_tx.output[0].value += Amount::from_sat(182);
            assert!(ctx.clone().process_proposal(proposal.clone()).is_ok());

            proposal.unsigned_tx.output[0].value -= Amount::from_sat(364);
            assert!(ctx.process_proposal(proposal).is_ok());

            Ok(())
        }

        #[test]
        fn test_process_proposal_when_output_value_decreased() -> Result<(), BoxError> {
            let mut ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            ctx.fee_contribution = None;
            proposal.unsigned_tx.output.get_mut(0).unwrap().value =
                ctx.original_psbt.unsigned_tx.output.get_mut(0).unwrap().value
                    - Amount::from_sat(1);

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::OutputValueDecreased.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_process_proposal_when_output_missing() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal: bitcoin::Psbt = PARSED_PAYJOIN_PROPOSAL.clone();

            proposal.unsigned_tx.output.clear();
            proposal.outputs.clear();

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::MissingOrShuffledOutputs.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_absolute_fee_less_than_original_psbt() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal = PARSED_PAYJOIN_PROPOSAL.clone();
            for output in proposal.outputs_mut() {
                output.bip32_derivation.clear();
            }
            for input in proposal.inputs_mut() {
                input.bip32_derivation.clear();
            }

            // Reduce the proposed fee to be less than the original fee
            proposal.unsigned_tx.output[0].value += bitcoin::Amount::from_sat(183);

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::AbsoluteFeeDecreased.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_payee_took_contributed_fee() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal = ctx.original_psbt.clone();

            for input in proposal.inputs_mut() {
                input.bip32_derivation.clear();
                input.partial_sigs.clear();
                input.final_script_sig = None;
                input.final_script_witness = None;
            }

            let redistributed_amount = Amount::from_sat(1);

            // Redistribute 1 sat between outputs so that the net on-chain fee doesn't increase
            let output_0 = proposal.unsigned_tx.output[0].value;
            proposal.unsigned_tx.output[0].value = output_0 - redistributed_amount;
            let output_1 = proposal.unsigned_tx.output[1].value;
            proposal.unsigned_tx.output[1].value = output_1 + redistributed_amount;

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::PayeeTookContributedFee.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_fee_contribution_pays_output_size_increase() -> Result<(), BoxError> {
            let ctx = create_psbt_context()?;
            let mut proposal = ctx.original_psbt.clone();

            for input in proposal.inputs_mut() {
                input.bip32_derivation.clear();
                input.partial_sigs.clear();
                input.final_script_sig = None;
                input.final_script_witness = None;
            }

            let contributed_fee = Amount::from_sat(10);
            let original_output = proposal.unsigned_tx.output[0].value;
            proposal.unsigned_tx.output[0].value = original_output - contributed_fee;

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::FeeContributionPaysOutputSizeIncrease.to_string()
            );

            Ok(())
        }

        #[test]
        fn test_fee_rate_below_minimum() -> Result<(), BoxError> {
            let mut ctx = create_psbt_context()?;
            let mut proposal = ctx.original_psbt.clone();

            for input in proposal.inputs_mut() {
                input.bip32_derivation.clear();
                input.partial_sigs.clear();
                input.final_script_sig = None;
                input.final_script_witness = None;
            }

            // The fee rate will always be below this min_fee_rate
            ctx.min_fee_rate = FeeRate::MAX;

            assert_eq!(
                ctx.process_proposal(proposal).unwrap_err().to_string(),
                InternalProposalError::FeeRateBelowMinimum.to_string()
            );

            Ok(())
        }
    }
}
