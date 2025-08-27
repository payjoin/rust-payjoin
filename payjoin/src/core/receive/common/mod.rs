//! Common typestates and methods for both BIP 77 v2 and BIP 78 v1.
//! This module isn't meant to be exposed publicly, but for v1 and v2
//! APIs to expose as relevant typestates.

use std::cmp::{max, min};

use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::rand::seq::SliceRandom;
use bitcoin::secp256k1::rand::{self, Rng};
use bitcoin::{Amount, FeeRate, Script, TxIn, TxOut, Weight};
use serde::{Deserialize, Serialize};

use super::error::{
    InputContributionError, InternalInputContributionError, InternalOutputSubstitutionError,
    InternalSelectionError,
};
use super::optional_parameters::Params;
use super::{InputPair, OutputSubstitutionError, ReplyableError, SelectionError};
use crate::output_substitution::OutputSubstitution;
use crate::psbt::PsbtExt;
use crate::receive::{InternalPayloadError, Original, PsbtContext};

/// Typestate which the receiver may substitute or add outputs to.
///
/// In addition to contributing new inputs to an existing PSBT, Payjoin allows the
/// receiver to substitute the original PSBT's outputs to potentially preserve privacy and batch transfers.
/// The receiver does not have to limit themselves to the address shared with the sender in the
/// original Payjoin URI, and can make substitutions of the existing outputs in the proposal.
///
/// Call [`Self::commit_outputs`] to proceed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WantsOutputs {
    pub(crate) original_psbt: Psbt,
    pub(crate) payjoin_psbt: Psbt,
    pub(crate) params: Params,
    pub(crate) change_vout: usize,
    pub(crate) owned_vouts: Vec<usize>,
}

impl WantsOutputs {
    /// Create a new [`WantsOutputs`] typestate from an [`Original`] typestate and a list of
    /// owned outputs.
    ///
    /// The first output in the `owned_vouts` list is used as the `change_vout`.
    pub(crate) fn new(original: Original, owned_vouts: Vec<usize>) -> Self {
        Self {
            original_psbt: original.psbt.clone(),
            payjoin_psbt: original.psbt,
            params: original.params,
            change_vout: owned_vouts[0],
            owned_vouts,
        }
    }

    /// Returns whether the receiver is allowed to substitute original outputs or not.
    pub fn output_substitution(&self) -> OutputSubstitution { self.params.output_substitution }

    /// Substitute the receiver output script with the provided script.
    pub fn substitute_receiver_script(
        self,
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
    pub fn replace_receiver_outputs(
        self,
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
                        if self.output_substitution() == OutputSubstitution::Disabled
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
                        if self.output_substitution() == OutputSubstitution::Disabled {
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
            original_psbt: self.original_psbt,
            payjoin_psbt,
            params: self.params,
            change_vout: change_vout.ok_or(InternalOutputSubstitutionError::InvalidDrainScript)?,
            owned_vouts: self.owned_vouts,
        })
    }

    /// Commits the outputs as final, and moves on to the next typestate.
    ///
    /// Outputs cannot be modified after this function is called.
    pub fn commit_outputs(self) -> WantsInputs {
        WantsInputs {
            original_psbt: self.original_psbt,
            payjoin_psbt: self.payjoin_psbt,
            params: self.params,
            change_vout: self.change_vout,
            receiver_inputs: vec![],
        }
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

/// Typestate for a checked proposal which the receiver may contribute inputs to.
///
/// Call [`Self::commit_inputs`] to proceed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WantsInputs {
    pub(crate) original_psbt: Psbt,
    pub(crate) payjoin_psbt: Psbt,
    pub(crate) params: Params,
    pub(crate) change_vout: usize,
    pub(crate) receiver_inputs: Vec<InputPair>,
}

impl WantsInputs {
    /// Selects and returns an input from `candidate_inputs` which will preserve the receiver's privacy by
    /// avoiding the Unnecessary Input Heuristic 2 (UIH2) outlined in [Unnecessary Input
    /// Heuristics and PayJoin Transactions by Ghesmati et al. (2022)](https://eprint.iacr.org/2022/589).
    ///
    /// Privacy preservation is only supported for 2-output transactions. If the PSBT has more than
    /// 2 outputs or if none of the candidates are suitable for avoiding UIH2, this function
    /// defaults to the first candidate in `candidate_inputs` list.
    pub fn try_preserving_privacy(
        &self,
        candidate_inputs: impl IntoIterator<Item = InputPair>,
    ) -> Result<InputPair, SelectionError> {
        let mut candidate_inputs = candidate_inputs.into_iter().peekable();

        self.avoid_uih(&mut candidate_inputs)
            .or_else(|_| self.select_first_candidate(&mut candidate_inputs))
    }

    /// Returns the candidate input which avoids the UIH2 defined in [Unnecessary Input
    /// Heuristics and PayJoin Transactions by Ghesmati et al. (2022)](https://eprint.iacr.org/2022/589).
    ///
    /// Based on the paper, we are looking for the candidate input which, when added to the
    /// transaction with 2 existing outputs, results in the minimum input amount to be lower than the minimum
    /// output amount. Note that when calculating the minimum output amount, we consider the
    /// post-contribution amounts, and expect the output which pays to the receiver to have its
    /// value increased by the amount of the candidate input.
    ///
    /// Errors if the transaction does not have exactly 2 outputs.
    pub(crate) fn avoid_uih(
        &self,
        candidate_inputs: impl IntoIterator<Item = InputPair>,
    ) -> Result<InputPair, SelectionError> {
        if self.payjoin_psbt.outputs.len() != 2 {
            return Err(InternalSelectionError::UnsupportedOutputLength.into());
        }

        let min_out_sats = self
            .payjoin_psbt
            .unsigned_tx
            .output
            .iter()
            .map(|output| output.value)
            .min()
            .unwrap_or(Amount::MAX_MONEY);

        let min_in_sats = self
            .payjoin_psbt
            .input_pairs()
            .filter_map(|input| input.previous_txout().ok().map(|txo| txo.value))
            .min()
            .unwrap_or(Amount::MAX_MONEY);

        let prior_payment_sats = self.payjoin_psbt.unsigned_tx.output[self.change_vout].value;

        for input_pair in candidate_inputs {
            let candidate_sats = input_pair.previous_txout().value;
            let candidate_min_out = min(min_out_sats, prior_payment_sats + candidate_sats);
            let candidate_min_in = min(min_in_sats, candidate_sats);

            if candidate_min_in > candidate_min_out {
                // The candidate avoids UIH2 but conforms to UIH1: Optimal change heuristic.
                // It implies the smallest output is the sender's change address.
                return Ok(input_pair);
            }
        }

        // No suitable privacy preserving selection found
        Err(InternalSelectionError::NotFound.into())
    }

    /// Returns the first candidate input in the provided list or errors if the list is empty.
    fn select_first_candidate(
        &self,
        candidate_inputs: impl IntoIterator<Item = InputPair>,
    ) -> Result<InputPair, SelectionError> {
        candidate_inputs.into_iter().next().ok_or(InternalSelectionError::Empty.into())
    }

    /// Contributes the provided list of inputs to the transaction at random indices. If the total input
    /// amount exceeds the total output amount after the contribution, adds all excess amount to
    /// the receiver change output.
    pub fn contribute_inputs(
        self,
        inputs: impl IntoIterator<Item = InputPair>,
    ) -> Result<WantsInputs, InputContributionError> {
        let mut payjoin_psbt = self.payjoin_psbt.clone();
        // The payjoin proposal must not introduce mixed input sequence numbers
        let original_sequence = self
            .original_psbt
            .unsigned_tx
            .input
            .first()
            .map(|input| input.sequence)
            .unwrap_or_default();

        let inputs = inputs.into_iter().collect::<Vec<_>>();

        // Insert contributions at random indices for privacy
        let mut rng = rand::thread_rng();
        let mut receiver_input_amount = Amount::ZERO;
        for input_pair in inputs.clone() {
            receiver_input_amount += input_pair.previous_txout().value;
            let index = rng.gen_range(0..=self.payjoin_psbt.unsigned_tx.input.len());
            payjoin_psbt.inputs.insert(index, input_pair.psbtin);
            payjoin_psbt
                .unsigned_tx
                .input
                .insert(index, TxIn { sequence: original_sequence, ..input_pair.txin });
        }

        // Add the receiver change amount to the receiver change output, if applicable
        let receiver_min_input_amount = self.receiver_min_input_amount();
        if receiver_input_amount >= receiver_min_input_amount {
            let change_amount = receiver_input_amount - receiver_min_input_amount;
            payjoin_psbt.unsigned_tx.output[self.change_vout].value += change_amount;
        } else {
            return Err(InternalInputContributionError::ValueTooLow.into());
        }

        let mut receiver_inputs = self.receiver_inputs;
        receiver_inputs.extend(inputs);

        Ok(WantsInputs {
            original_psbt: self.original_psbt,
            payjoin_psbt,
            params: self.params,
            change_vout: self.change_vout,
            receiver_inputs,
        })
    }

    // Compute the minimum amount that the receiver must contribute to the transaction as input.
    fn receiver_min_input_amount(&self) -> Amount {
        let output_amount = self
            .payjoin_psbt
            .unsigned_tx
            .output
            .iter()
            .fold(Amount::ZERO, |acc, output| acc + output.value);
        let original_output_amount = self
            .original_psbt
            .unsigned_tx
            .output
            .iter()
            .fold(Amount::ZERO, |acc, output| acc + output.value);
        output_amount.checked_sub(original_output_amount).unwrap_or(Amount::ZERO)
    }

    /// Commits the inputs as final, and moves on to the next typestate.
    ///
    /// Inputs cannot be modified after this function is called.
    pub fn commit_inputs(self) -> WantsFeeRange {
        WantsFeeRange {
            original_psbt: self.original_psbt,
            payjoin_psbt: self.payjoin_psbt,
            params: self.params,
            change_vout: self.change_vout,
            receiver_inputs: self.receiver_inputs,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WantsFeeRange {
    pub(crate) original_psbt: Psbt,
    pub(crate) payjoin_psbt: Psbt,
    pub(crate) params: Params,
    pub(crate) change_vout: usize,
    pub(crate) receiver_inputs: Vec<InputPair>,
}

impl WantsFeeRange {
    pub(crate) fn apply_fee(
        &mut self,
        min_fee_rate: Option<FeeRate>,
        max_effective_fee_rate: Option<FeeRate>,
    ) -> Result<&Psbt, InternalPayloadError> {
        let min_fee_rate = min_fee_rate.unwrap_or(FeeRate::BROADCAST_MIN);
        log::trace!("min_fee_rate: {min_fee_rate:?}");
        log::trace!("params.min_fee_rate: {:?}", self.params.min_fee_rate);
        let min_fee_rate = max(min_fee_rate, self.params.min_fee_rate);
        log::debug!("min_fee_rate: {min_fee_rate:?}");

        let max_fee_rate = max_effective_fee_rate.unwrap_or(FeeRate::BROADCAST_MIN);

        // If the sender specified a fee contribution, the receiver is allowed to decrease the
        // sender's fee output to pay for additional input fees. Any fees in excess of
        // `max_additional_fee_contribution` must be covered by the receiver.
        let input_contribution_weight = self.additional_input_weight()?;
        let additional_fee = input_contribution_weight * min_fee_rate;
        log::trace!("additional_fee: {additional_fee}");
        let mut receiver_additional_fee = additional_fee;
        if additional_fee >= Amount::ONE_SAT {
            log::trace!(
                "self.params.additional_fee_contribution: {:?}",
                self.params.additional_fee_contribution
            );
            if let Some((max_additional_fee_contribution, additional_fee_output_index)) =
                self.params.additional_fee_contribution
            {
                // Find the sender's specified output in the original psbt.
                // This step is necessary because the sender output may have shifted if new
                // receiver outputs were added to the payjoin psbt.
                let sender_fee_output =
                    &self.original_psbt.unsigned_tx.output[additional_fee_output_index];
                // Find the index of that output in the payjoin psbt
                let sender_fee_vout = self
                    .payjoin_psbt
                    .unsigned_tx
                    .output
                    .iter()
                    .position(|txo| txo.script_pubkey == sender_fee_output.script_pubkey)
                    .expect("Sender output is missing from payjoin PSBT");
                // Determine the additional amount that the sender will pay in fees
                let sender_additional_fee = min(max_additional_fee_contribution, additional_fee);
                log::trace!("sender_additional_fee: {sender_additional_fee}");
                // Remove additional miner fee from the sender's specified output
                self.payjoin_psbt.unsigned_tx.output[sender_fee_vout].value -=
                    sender_additional_fee;
                receiver_additional_fee -= sender_additional_fee;
            }
        }

        // The sender's fee contribution can only be used to pay for additional input weight, so
        // any additional outputs must be paid for by the receiver.
        let output_contribution_weight = self.additional_output_weight();
        receiver_additional_fee += output_contribution_weight * min_fee_rate;
        log::trace!("receiver_additional_fee: {receiver_additional_fee}");
        // Ensure that the receiver does not pay more in fees
        // than they would by building a separate transaction at max_effective_fee_rate instead.
        let max_fee = (input_contribution_weight + output_contribution_weight) * max_fee_rate;
        log::trace!("max_fee: {max_fee}");
        if receiver_additional_fee > max_fee {
            let proposed_fee_rate =
                receiver_additional_fee / (input_contribution_weight + output_contribution_weight);
            return Err(InternalPayloadError::FeeTooHigh(proposed_fee_rate, max_fee_rate));
        }
        if receiver_additional_fee >= Amount::ONE_SAT {
            // Remove additional miner fee from the receiver's specified output
            self.payjoin_psbt.unsigned_tx.output[self.change_vout].value -= receiver_additional_fee;
        }
        Ok(&self.payjoin_psbt)
    }

    /// Calculate the additional input weight contributed by the receiver.
    pub(crate) fn additional_input_weight(&self) -> Result<Weight, InternalPayloadError> {
        Ok(self.receiver_inputs.iter().map(|input_pair| input_pair.expected_weight).sum())
    }

    /// Calculate the additional output weight contributed by the receiver.
    fn additional_output_weight(&self) -> Weight {
        let payjoin_outputs_weight = self
            .payjoin_psbt
            .unsigned_tx
            .output
            .iter()
            .fold(Weight::ZERO, |acc, txo| acc + txo.weight());
        let original_outputs_weight = self
            .original_psbt
            .unsigned_tx
            .output
            .iter()
            .fold(Weight::ZERO, |acc, txo| acc + txo.weight());
        let output_contribution_weight = payjoin_outputs_weight - original_outputs_weight;
        log::trace!("output_contribution_weight : {output_contribution_weight}");
        output_contribution_weight
    }

    /// Applies additional fee contribution now that the receiver has contributed inputs
    /// and may have added new outputs.
    ///
    /// How much the receiver ends up paying for fees depends on how much the sender stated they
    /// were willing to pay in the parameters of the original proposal. For additional
    /// inputs, fees will be subtracted from the sender's outputs as much as possible until we hit
    /// the limit the sender specified in the Payjoin parameters. Any remaining fees for the new inputs
    /// will be then subtracted from the change output of the receiver.
    /// Fees for additional outputs are always subtracted from the receiver's outputs.
    ///
    /// `max_effective_fee_rate` is the maximum effective fee rate that the receiver is
    /// willing to pay for their own input/output contributions. A `max_effective_fee_rate`
    /// of zero indicates that the receiver is not willing to pay any additional
    /// fees. Errors if the final effective fee rate exceeds `max_effective_fee_rate`.
    ///
    /// If not provided, `min_fee_rate` and `max_effective_fee_rate` default to the
    /// minimum possible relay fee.
    ///
    /// The minimum effective fee limit is the highest of the minimum limit set by the sender in
    /// the original proposal parameters and the limit passed in the `min_fee_rate` parameter.
    pub(crate) fn _apply_fee_range(
        mut self,
        min_fee_rate: Option<FeeRate>,
        max_effective_fee_rate: Option<FeeRate>,
    ) -> Result<PsbtContext, ReplyableError> {
        let psbt = self.apply_fee(min_fee_rate, max_effective_fee_rate)?.clone();
        Ok(PsbtContext { original_psbt: self.original_psbt, payjoin_psbt: psbt })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::key::rand::rngs::StdRng;
    use bitcoin::key::rand::SeedableRng;
    use payjoin_test_utils::RECEIVER_INPUT_CONTRIBUTION;

    use super::*;
    use crate::receive::tests::original_from_test_vector;

    #[test]
    fn empty_candidates_inputs() {
        let original = original_from_test_vector();
        let wants_inputs = WantsOutputs::new(original, vec![0]).commit_outputs();
        let empty_candidate_inputs: Vec<InputPair> = vec![];
        let result = wants_inputs.try_preserving_privacy(empty_candidate_inputs);
        assert_eq!(
            result.unwrap_err(),
            SelectionError::from(InternalSelectionError::Empty),
            "try_preserving_privacy should fail with empty candidate inputs"
        );
    }

    #[test]
    fn test_pjos_disabled() {
        let mut original = original_from_test_vector();
        original.params.output_substitution = OutputSubstitution::Disabled;
        let wants_outputs = WantsOutputs::new(original, vec![0]);
        let script_pubkey = &wants_outputs.original_psbt.unsigned_tx.output
            [wants_outputs.change_vout]
            .script_pubkey;

        let output_value =
            wants_outputs.original_psbt.unsigned_tx.output[wants_outputs.change_vout].value;
        let outputs = vec![TxOut { value: output_value, script_pubkey: script_pubkey.clone() }];
        let unchanged_amount =
            wants_outputs.clone().replace_receiver_outputs(outputs, script_pubkey.as_script());
        assert!(
            unchanged_amount.is_ok(),
            "Not touching the receiver output amount is always allowed"
        );
        assert_ne!(wants_outputs.payjoin_psbt, unchanged_amount.unwrap().payjoin_psbt);

        let output_value =
            wants_outputs.original_psbt.unsigned_tx.output[wants_outputs.change_vout].value
                + Amount::ONE_SAT;
        let outputs = vec![TxOut { value: output_value, script_pubkey: script_pubkey.clone() }];
        let increased_amount =
            wants_outputs.clone().replace_receiver_outputs(outputs, script_pubkey.as_script());
        assert!(
            increased_amount.is_ok(),
            "Increasing the receiver output amount is always allowed"
        );
        assert_ne!(wants_outputs.payjoin_psbt, increased_amount.unwrap().payjoin_psbt);

        let output_value =
            wants_outputs.original_psbt.unsigned_tx.output[wants_outputs.change_vout].value
                - Amount::ONE_SAT;
        let outputs = vec![TxOut { value: output_value, script_pubkey: script_pubkey.clone() }];
        let decreased_amount =
            wants_outputs.clone().replace_receiver_outputs(outputs, script_pubkey.as_script());
        assert_eq!(
            decreased_amount.unwrap_err(),
            OutputSubstitutionError::from(
                InternalOutputSubstitutionError::DecreasedValueWhenDisabled
            ),
            "Payjoin receiver amount has been decreased and should error"
        );

        let script = Script::new();
        let replace_receiver_script_pubkey = wants_outputs.substitute_receiver_script(script);
        assert_eq!(
            replace_receiver_script_pubkey.unwrap_err(),
            OutputSubstitutionError::from(
                InternalOutputSubstitutionError::ScriptPubKeyChangedWhenDisabled
            ),
            "Payjoin receiver script pubkey has been modified and should error"
        );
    }

    #[test]
    fn test_avoid_uih_one_output() {
        let original = original_from_test_vector();
        let proposal_psbt = Psbt::from_str(RECEIVER_INPUT_CONTRIBUTION).unwrap();
        let input = InputPair::new(
            proposal_psbt.unsigned_tx.input[1].clone(),
            proposal_psbt.inputs[1].clone(),
            None,
        )
        .unwrap();
        let input_iter = [input].into_iter();
        let mut payjoin = WantsOutputs::new(original, vec![0])
            .commit_outputs()
            .contribute_inputs(input_iter.clone())
            .expect("Failed to contribute inputs");

        payjoin.payjoin_psbt.outputs.pop();
        let avoid_uih = payjoin.avoid_uih(input_iter);
        assert_eq!(
            avoid_uih.unwrap_err(),
            SelectionError::from(InternalSelectionError::UnsupportedOutputLength),
            "Payjoin below minimum allowed outputs for avoid uih and should error"
        );
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
