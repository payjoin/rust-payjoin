//! Receive Payjoin
//!
//! This module contains types and methods used to receive payjoin via BIP78.
//! Usage is pretty simple:
//!
//! 1. Generate a pj_uri [BIP 21](https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki)
//!    using [`payjoin::Uri`](crate::Uri)::from_str
//! 2. Listen for a sender's request on the `pj` endpoint
//! 3. Parse the request using
//!    [`UncheckedProposal::from_request()`](crate::receive::UncheckedProposal::from_request())
//! 4. Validate the proposal using the `check` methods to guide you.
//! 5. Assuming the proposal is valid, augment it into a payjoin with the available
//!    `try_preserving_privacy` and `contribute` methods
//! 6. Extract the payjoin PSBT and sign it
//! 7. Respond to the sender's http request with the signed PSBT as payload.
//!
//! The `receive` feature provides all of the check methods, PSBT data manipulation, coin
//! selection, and transport structures to receive payjoin and handle errors in a privacy
//! preserving way.
//!
//! Receiving payjoin entails listening to a secure http endpoint for inbound requests.  The
//! endpoint is displayed in the `pj` parameter of a [bip
//! 21](https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki) request URI.
//!
//! [reference implementation](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-cli)

use std::cmp::{max, min};

use bitcoin::base64::prelude::BASE64_STANDARD;
use bitcoin::base64::Engine;
use bitcoin::psbt::Psbt;
use bitcoin::{Amount, FeeRate, OutPoint, Script, TxOut, Weight};

mod error;
mod optional_parameters;
#[cfg(feature = "v2")]
pub mod v2;

use bitcoin::secp256k1::rand::seq::SliceRandom;
use bitcoin::secp256k1::rand::{self, Rng};
pub use error::{
    Error, InputContributionError, OutputSubstitutionError, RequestError, SelectionError,
};
use error::{
    InternalInputContributionError, InternalOutputSubstitutionError, InternalRequestError,
    InternalSelectionError,
};
use optional_parameters::Params;

use crate::psbt::PsbtExt;

pub trait Headers {
    fn get_header(&self, key: &str) -> Option<&str>;
}

/// The sender's original PSBT and optional parameters
///
/// This type is used to process the request. It is returned by
/// [`UncheckedProposal::from_request()`](crate::receive::UncheckedProposal::from_request()).
///
/// If you are implementing an interactive payment processor, you should get extract the original
/// transaction with extract_tx_to_schedule_broadcast() and schedule, followed by checking
/// that the transaction can be broadcast with check_broadcast_suitability. Otherwise it is safe to
/// call assume_interactive_receive to proceed with validation.
#[derive(Debug, Clone)]
pub struct UncheckedProposal {
    psbt: Psbt,
    params: Params,
}

impl UncheckedProposal {
    pub fn from_request(
        mut body: impl std::io::Read,
        query: &str,
        headers: impl Headers,
    ) -> Result<Self, RequestError> {
        let content_type = headers
            .get_header("content-type")
            .ok_or(InternalRequestError::MissingHeader("Content-Type"))?;
        if !content_type.starts_with("text/plain") {
            return Err(InternalRequestError::InvalidContentType(content_type.to_owned()).into());
        }
        let content_length = headers
            .get_header("content-length")
            .ok_or(InternalRequestError::MissingHeader("Content-Length"))?
            .parse::<u64>()
            .map_err(InternalRequestError::InvalidContentLength)?;
        // 4M block size limit with base64 encoding overhead => maximum reasonable size of content-length
        if content_length > 4_000_000 * 4 / 3 {
            return Err(InternalRequestError::ContentLengthTooLarge(content_length).into());
        }

        // enforce the limit
        let mut buf = vec![0; content_length as usize]; // 4_000_000 * 4 / 3 fits in u32
        body.read_exact(&mut buf).map_err(InternalRequestError::Io)?;
        let base64 = BASE64_STANDARD.decode(&buf).map_err(InternalRequestError::Base64)?;
        let unchecked_psbt = Psbt::deserialize(&base64).map_err(InternalRequestError::Psbt)?;

        let psbt = unchecked_psbt.validate().map_err(InternalRequestError::InconsistentPsbt)?;
        log::debug!("Received original psbt: {:?}", psbt);

        let pairs = url::form_urlencoded::parse(query.as_bytes());
        let params = Params::from_query_pairs(pairs).map_err(InternalRequestError::SenderParams)?;
        log::debug!("Received request with params: {:?}", params);

        // TODO check that params are valid for the request's Original PSBT

        Ok(UncheckedProposal { psbt, params })
    }

    /// The Sender's Original PSBT transaction
    pub fn extract_tx_to_schedule_broadcast(&self) -> bitcoin::Transaction {
        self.psbt.clone().extract_tx_unchecked_fee_rate()
    }

    fn psbt_fee_rate(&self) -> Result<FeeRate, Error> {
        let original_psbt_fee = self.psbt.fee().map_err(InternalRequestError::Psbt)?;
        Ok(original_psbt_fee / self.extract_tx_to_schedule_broadcast().weight())
    }

    /// Check that the Original PSBT can be broadcasted.
    ///
    /// Receiver MUST check that the Original PSBT from the sender
    /// can be broadcast, i.e. `testmempoolaccept` bitcoind rpc returns { "allowed": true,.. }.
    ///
    /// Receiver can optionaly set a minimum feerate that will be enforced on the Original PSBT.
    /// This can be used to prevent probing attacks and make it easier to deal with
    /// high feerate environments.
    ///
    /// Do this check if you generate bitcoin uri to receive Payjoin on sender request without manual human approval, like a payment processor.
    /// Such so called "non-interactive" receivers are otherwise vulnerable to probing attacks.
    /// If a sender can make requests at will, they can learn which bitcoin the receiver owns at no cost.
    /// Broadcasting the Original PSBT after some time in the failure case makes incurs sender cost and prevents probing.
    ///
    /// Call this after checking downstream.
    pub fn check_broadcast_suitability(
        self,
        min_fee_rate: Option<FeeRate>,
        can_broadcast: impl Fn(&bitcoin::Transaction) -> Result<bool, Error>,
    ) -> Result<MaybeInputsOwned, Error> {
        let original_psbt_fee_rate = self.psbt_fee_rate()?;
        if let Some(min_fee_rate) = min_fee_rate {
            if original_psbt_fee_rate < min_fee_rate {
                return Err(InternalRequestError::PsbtBelowFeeRate(
                    original_psbt_fee_rate,
                    min_fee_rate,
                )
                .into());
            }
        }
        if can_broadcast(&self.psbt.clone().extract_tx_unchecked_fee_rate())? {
            Ok(MaybeInputsOwned { psbt: self.psbt, params: self.params })
        } else {
            Err(InternalRequestError::OriginalPsbtNotBroadcastable.into())
        }
    }

    /// Call this method if the only way to initiate a Payjoin with this receiver
    /// requires manual intervention, as in most consumer wallets.
    ///
    /// So-called "non-interactive" receivers, like payment processors, that allow arbitrary requests are otherwise vulnerable to probing attacks.
    /// Those receivers call `extract_tx_to_check_broadcast()` and `attest_tested_and_scheduled_broadcast()` after making those checks downstream.
    pub fn assume_interactive_receiver(self) -> MaybeInputsOwned {
        MaybeInputsOwned { psbt: self.psbt, params: self.params }
    }
}

/// Typestate to validate that the Original PSBT has no receiver-owned inputs.
///
/// Call [`check_no_receiver_owned_inputs()`](struct.UncheckedProposal.html#method.check_no_receiver_owned_inputs) to proceed.
#[derive(Clone)]
pub struct MaybeInputsOwned {
    psbt: Psbt,
    params: Params,
}

impl MaybeInputsOwned {
    /// Check that the Original PSBT has no receiver-owned inputs.
    /// Return original-psbt-rejected error or otherwise refuse to sign undesirable inputs.
    ///
    /// An attacker could try to spend receiver's own inputs. This check prevents that.
    pub fn check_inputs_not_owned(
        self,
        is_owned: impl Fn(&Script) -> Result<bool, Error>,
    ) -> Result<MaybeMixedInputScripts, Error> {
        let mut err = Ok(());
        if let Some(e) = self
            .psbt
            .input_pairs()
            .scan(&mut err, |err, input| match input.previous_txout() {
                Ok(txout) => Some(txout.script_pubkey.to_owned()),
                Err(e) => {
                    **err = Err(Error::BadRequest(InternalRequestError::PrevTxOut(e).into()));
                    None
                }
            })
            .find_map(|script| match is_owned(&script) {
                Ok(false) => None,
                Ok(true) =>
                    Some(Error::BadRequest(InternalRequestError::InputOwned(script).into())),
                Err(e) => Some(Error::Server(e.into())),
            })
        {
            return Err(e);
        }
        err?;

        Ok(MaybeMixedInputScripts { psbt: self.psbt, params: self.params })
    }
}

/// Typestate to validate that the Original PSBT has no mixed input types.
///
/// Call [`check_no_mixed_input_types`](struct.UncheckedProposal.html#method.check_no_mixed_input_scripts) to proceed.
#[derive(Clone)]
pub struct MaybeMixedInputScripts {
    psbt: Psbt,
    params: Params,
}

impl MaybeMixedInputScripts {
    /// Verify the original transaction did not have mixed input types
    /// Call this after checking downstream.
    ///
    /// Note: mixed spends do not necessarily indicate distinct wallet fingerprints.
    /// This check is intended to prevent some types of wallet fingerprinting.
    pub fn check_no_mixed_input_scripts(self) -> Result<MaybeInputsSeen, RequestError> {
        let mut err = Ok(());
        let input_scripts = self
            .psbt
            .input_pairs()
            .scan(&mut err, |err, input| match input.address_type() {
                Ok(address_type) => Some(address_type),
                Err(e) => {
                    **err = Err(RequestError::from(InternalRequestError::AddressType(e)));
                    None
                }
            })
            .collect::<Vec<_>>();
        err?;

        if let Some(first) = input_scripts.first() {
            input_scripts.iter().try_for_each(|input_type| {
                if input_type != first {
                    Err(RequestError::from(InternalRequestError::MixedInputScripts(
                        *first,
                        *input_type,
                    )))
                } else {
                    Ok(())
                }
            })?;
        }

        Ok(MaybeInputsSeen { psbt: self.psbt, params: self.params })
    }
}

/// Typestate to validate that the Original PSBT has no inputs that have been seen before.
///
/// Call [`check_no_inputs_seen`](struct.MaybeInputsSeen.html#method.check_no_inputs_seen_before) to proceed.
#[derive(Clone)]
pub struct MaybeInputsSeen {
    psbt: Psbt,
    params: Params,
}
impl MaybeInputsSeen {
    /// Make sure that the original transaction inputs have never been seen before.
    /// This prevents probing attacks. This prevents reentrant Payjoin, where a sender
    /// proposes a Payjoin PSBT as a new Original PSBT for a new Payjoin.
    pub fn check_no_inputs_seen_before(
        self,
        is_known: impl Fn(&OutPoint) -> Result<bool, Error>,
    ) -> Result<OutputsUnknown, Error> {
        self.psbt.input_pairs().try_for_each(|input| {
            match is_known(&input.txin.previous_output) {
                Ok(false) => Ok::<(), Error>(()),
                Ok(true) =>  {
                    log::warn!("Request contains an input we've seen before: {}. Preventing possible probing attack.", input.txin.previous_output);
                    Err(Error::BadRequest(
                        InternalRequestError::InputSeen(input.txin.previous_output).into(),
                    ))?
                },
                Err(e) => Err(Error::Server(e.into()))?,
            }
        })?;

        Ok(OutputsUnknown { psbt: self.psbt, params: self.params })
    }
}

/// The receiver has not yet identified which outputs belong to the receiver.
///
/// Only accept PSBTs that send us money.
/// Identify those outputs with `identify_receiver_outputs()` to proceed
#[derive(Clone)]
pub struct OutputsUnknown {
    psbt: Psbt,
    params: Params,
}

impl OutputsUnknown {
    /// Find which outputs belong to the receiver
    pub fn identify_receiver_outputs(
        self,
        is_receiver_output: impl Fn(&Script) -> Result<bool, Error>,
    ) -> Result<WantsOutputs, Error> {
        let owned_vouts: Vec<usize> = self
            .psbt
            .unsigned_tx
            .output
            .iter()
            .enumerate()
            .filter_map(|(vout, txo)| match is_receiver_output(&txo.script_pubkey) {
                Ok(true) => Some(Ok(vout)),
                Ok(false) => None,
                Err(e) => Some(Err(e)),
            })
            .collect::<Result<Vec<_>, _>>()?;

        if owned_vouts.is_empty() {
            return Err(Error::BadRequest(InternalRequestError::MissingPayment.into()));
        }

        let mut params = self.params.clone();
        if let Some((_, additional_fee_output_index)) = params.additional_fee_contribution {
            // If the additional fee output index specified by the sender is pointing to a receiver output,
            // the receiver should ignore the parameter.
            if owned_vouts.contains(&additional_fee_output_index) {
                params.additional_fee_contribution = None;
            }
        }

        Ok(WantsOutputs {
            original_psbt: self.psbt.clone(),
            payjoin_psbt: self.psbt,
            params,
            change_vout: owned_vouts[0],
            owned_vouts,
        })
    }
}

/// A checked proposal that the receiver may substitute or add outputs to
#[derive(Debug, Clone)]
pub struct WantsOutputs {
    original_psbt: Psbt,
    payjoin_psbt: Psbt,
    params: Params,
    change_vout: usize,
    owned_vouts: Vec<usize>,
}

impl WantsOutputs {
    pub fn is_output_substitution_disabled(&self) -> bool {
        self.params.disable_output_substitution
    }

    /// Substitute the receiver output script with the provided script.
    pub fn substitute_receiver_script(
        self,
        output_script: &Script,
    ) -> Result<WantsOutputs, OutputSubstitutionError> {
        let output_value = self.original_psbt.unsigned_tx.output[self.change_vout].value;
        let outputs = vec![TxOut { value: output_value, script_pubkey: output_script.into() }];
        self.replace_receiver_outputs(outputs, output_script)
    }

    /// Replace **all** receiver outputs with one or more provided outputs.
    /// The drain script specifies which address to *drain* coins to. An output corresponding to
    /// that address must be included in `replacement_outputs`. The value of that output may be
    /// increased or decreased depending on the receiver's input contributions and whether the
    /// receiver needs to pay for additional miner fees (e.g. in the case of adding many outputs).
    pub fn replace_receiver_outputs(
        self,
        replacement_outputs: Vec<TxOut>,
        drain_script: &Script,
    ) -> Result<WantsOutputs, OutputSubstitutionError> {
        let mut payjoin_psbt = self.original_psbt.clone();
        let mut outputs = vec![];
        let mut replacement_outputs = replacement_outputs.clone();
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
                        if self.params.disable_output_substitution
                            && txo.value < original_output.value
                        {
                            return Err(
                                InternalOutputSubstitutionError::OutputSubstitutionDisabled(
                                    "Decreasing the receiver output value is not allowed",
                                )
                                .into(),
                            );
                        }
                        outputs.push(txo);
                    }
                    // Otherwise randomly select one of the replacement outputs
                    None => {
                        if self.params.disable_output_substitution {
                            return Err(
                                InternalOutputSubstitutionError::OutputSubstitutionDisabled(
                                    "Changing the receiver output script pubkey is not allowed",
                                )
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
        Ok(WantsOutputs {
            original_psbt: self.original_psbt,
            payjoin_psbt,
            params: self.params,
            change_vout: change_vout.ok_or(InternalOutputSubstitutionError::InvalidDrainScript)?,
            owned_vouts: self.owned_vouts,
        })
    }

    /// Proceed to the input contribution step.
    /// Outputs cannot be modified after this function is called.
    pub fn commit_outputs(self) -> WantsInputs {
        WantsInputs {
            original_psbt: self.original_psbt,
            payjoin_psbt: self.payjoin_psbt,
            params: self.params,
            change_vout: self.change_vout,
        }
    }
}

/// Shuffles `new` vector, then interleaves its elements with those from `original`,
/// maintaining the relative order in `original` but randomly inserting elements from `new`.
/// The combined result replaces the contents of `original`.
fn interleave_shuffle<T: Clone, R: rand::Rng>(
    original: &mut Vec<T>,
    new: &mut Vec<T>,
    rng: &mut R,
) {
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

/// A checked proposal that the receiver may contribute inputs to to make a payjoin
#[derive(Debug, Clone)]
pub struct WantsInputs {
    original_psbt: Psbt,
    payjoin_psbt: Psbt,
    params: Params,
    change_vout: usize,
}

impl WantsInputs {
    /// Select receiver input such that the payjoin avoids surveillance.
    /// Return the input chosen that has been applied to the Proposal.
    ///
    /// Proper coin selection allows payjoin to resemble ordinary transactions.
    /// To ensure the resemblance, a number of heuristics must be avoided.
    ///
    /// UIH "Unnecessary input heuristic" is avoided for multi-output transactions.
    /// A simple consolidation is otherwise chosen if available.
    pub fn try_preserving_privacy(
        &self,
        candidate_inputs: impl IntoIterator<Item = (Amount, OutPoint)>,
    ) -> Result<OutPoint, SelectionError> {
        let mut candidate_inputs = candidate_inputs.into_iter().peekable();
        if candidate_inputs.peek().is_none() {
            return Err(InternalSelectionError::Empty.into());
        }

        if self.payjoin_psbt.outputs.len() > 2 {
            // This UIH avoidance function supports only
            // many-input, n-output transactions such that n <= 2 for now
            return Err(InternalSelectionError::TooManyOutputs.into());
        }

        if self.payjoin_psbt.outputs.len() == 2 {
            self.avoid_uih(candidate_inputs)
        } else {
            self.select_first_candidate(candidate_inputs)
        }
    }

    /// UIH "Unnecessary input heuristic" is one class of heuristics to avoid. We define
    /// UIH1 and UIH2 according to the BlockSci practice
    /// BlockSci UIH1 and UIH2:
    /// if min(in) > min(out) then UIH1 else UIH2
    /// https://eprint.iacr.org/2022/589.pdf
    fn avoid_uih(
        &self,
        candidate_inputs: impl IntoIterator<Item = (Amount, OutPoint)>,
    ) -> Result<OutPoint, SelectionError> {
        let min_original_out_sats = self
            .payjoin_psbt
            .unsigned_tx
            .output
            .iter()
            .map(|output| output.value)
            .min()
            .unwrap_or(Amount::MAX_MONEY);

        let min_original_in_sats = self
            .payjoin_psbt
            .input_pairs()
            .filter_map(|input| input.previous_txout().ok().map(|txo| txo.value))
            .min()
            .unwrap_or(Amount::MAX_MONEY);

        let prior_payment_sats = self.payjoin_psbt.unsigned_tx.output[self.change_vout].value;

        for candidate in candidate_inputs {
            let candidate_sats = candidate.0;
            let candidate_min_out = min(min_original_out_sats, prior_payment_sats + candidate_sats);
            let candidate_min_in = min(min_original_in_sats, candidate_sats);

            if candidate_min_in > candidate_min_out {
                // The candidate avoids UIH2 but conforms to UIH1: Optimal change heuristic.
                // It implies the smallest output is the sender's change address.
                return Ok(candidate.1);
            }
        }

        // No suitable privacy preserving selection found
        Err(InternalSelectionError::NotFound.into())
    }

    fn select_first_candidate(
        &self,
        candidate_inputs: impl IntoIterator<Item = (Amount, OutPoint)>,
    ) -> Result<OutPoint, SelectionError> {
        candidate_inputs
            .into_iter()
            .next()
            .map_or(Err(InternalSelectionError::NotFound.into()), |(_, outpoint)| Ok(outpoint))
    }

    /// Add the provided list of inputs to the transaction.
    /// Any excess input amount is added to the change_vout output indicated previously.
    pub fn contribute_witness_inputs(
        self,
        inputs: impl IntoIterator<Item = (OutPoint, TxOut)>,
    ) -> Result<WantsInputs, InputContributionError> {
        let mut payjoin_psbt = self.payjoin_psbt.clone();
        // The payjoin proposal must not introduce mixed input sequence numbers
        let original_sequence = self
            .payjoin_psbt
            .unsigned_tx
            .input
            .first()
            .map(|input| input.sequence)
            .unwrap_or_default();

        // Insert contributions at random indices for privacy
        let mut rng = rand::thread_rng();
        let mut receiver_input_amount = Amount::ZERO;
        for (outpoint, txo) in inputs.into_iter() {
            receiver_input_amount += txo.value;
            let index = rng.gen_range(0..=self.payjoin_psbt.unsigned_tx.input.len());
            payjoin_psbt.inputs.insert(
                index,
                bitcoin::psbt::Input { witness_utxo: Some(txo), ..Default::default() },
            );
            payjoin_psbt.unsigned_tx.input.insert(
                index,
                bitcoin::TxIn {
                    previous_output: outpoint,
                    sequence: original_sequence,
                    ..Default::default()
                },
            );
        }

        // Add the receiver change amount to the receiver change output, if applicable
        let receiver_min_input_amount = self.receiver_min_input_amount();
        if receiver_input_amount >= receiver_min_input_amount {
            let change_amount = receiver_input_amount - receiver_min_input_amount;
            payjoin_psbt.unsigned_tx.output[self.change_vout].value += change_amount;
        } else {
            return Err(InternalInputContributionError::ValueTooLow.into());
        }

        Ok(WantsInputs {
            original_psbt: self.original_psbt,
            payjoin_psbt,
            params: self.params,
            change_vout: self.change_vout,
        })
    }

    // Compute the minimum amount that the receiver must contribute to the transaction as input
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

    /// Proceed to the proposal finalization step.
    /// Inputs cannot be modified after this function is called.
    pub fn commit_inputs(self) -> ProvisionalProposal {
        ProvisionalProposal {
            original_psbt: self.original_psbt,
            payjoin_psbt: self.payjoin_psbt,
            params: self.params,
            change_vout: self.change_vout,
        }
    }
}

/// A checked proposal that the receiver may sign and finalize to make a proposal PSBT that the
/// sender will accept.
#[derive(Debug, Clone)]
pub struct ProvisionalProposal {
    original_psbt: Psbt,
    payjoin_psbt: Psbt,
    params: Params,
    change_vout: usize,
}

impl ProvisionalProposal {
    /// Apply additional fee contribution now that the receiver has contributed input
    /// this is kind of a "build_proposal" step before we sign and finalize and extract
    ///
    /// max_feerate is the maximum effective feerate that the receiver is willing to pay for their
    /// own input/output contributions. A max_feerate of zero indicates that the receiver is not
    /// willing to pay any additional fees.
    fn apply_fee(
        &mut self,
        min_feerate: Option<FeeRate>,
        max_feerate: FeeRate,
    ) -> Result<&Psbt, RequestError> {
        let min_feerate = min_feerate.unwrap_or(FeeRate::MIN);
        log::trace!("min_feerate: {:?}", min_feerate);
        log::trace!("params.min_feerate: {:?}", self.params.min_feerate);
        let min_feerate = max(min_feerate, self.params.min_feerate);
        log::debug!("min_feerate: {:?}", min_feerate);

        // If the sender specified a fee contribution, the receiver is allowed to decrease the
        // sender's fee output to pay for additional input fees. Any fees in excess of
        // `max_additional_fee_contribution` must be covered by the receiver.
        let input_contribution_weight = self.additional_input_weight()?;
        let additional_fee = input_contribution_weight * min_feerate;
        log::trace!("additional_fee: {}", additional_fee);
        let mut receiver_additional_fee = additional_fee;
        if additional_fee > Amount::ZERO {
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
                log::trace!("sender_additional_fee: {}", sender_additional_fee);
                // Remove additional miner fee from the sender's specified output
                self.payjoin_psbt.unsigned_tx.output[sender_fee_vout].value -=
                    sender_additional_fee;
                receiver_additional_fee -= sender_additional_fee;
            }
        }

        // The sender's fee contribution can only be used to pay for additional input weight, so
        // any additional outputs must be paid for by the receiver.
        let output_contribution_weight = self.additional_output_weight();
        receiver_additional_fee += output_contribution_weight * min_feerate;
        log::trace!("receiver_additional_fee: {}", receiver_additional_fee);
        // Ensure that the receiver does not pay more in fees
        // than they would by building a separate transaction at max_feerate instead.
        let max_fee = (input_contribution_weight + output_contribution_weight) * max_feerate;
        log::trace!("max_fee: {}", max_fee);
        if receiver_additional_fee > max_fee {
            let proposed_feerate =
                receiver_additional_fee / (input_contribution_weight + output_contribution_weight);
            return Err(InternalRequestError::FeeTooHigh(proposed_feerate, max_feerate).into());
        }
        if receiver_additional_fee > Amount::ZERO {
            // Remove additional miner fee from the receiver's specified output
            self.payjoin_psbt.unsigned_tx.output[self.change_vout].value -= receiver_additional_fee;
        }
        Ok(&self.payjoin_psbt)
    }

    /// Calculate the additional input weight contributed by the receiver
    fn additional_input_weight(&self) -> Result<Weight, RequestError> {
        // This error should never happen. We check for at least one input in the constructor
        let input_pair = self
            .payjoin_psbt
            .input_pairs()
            .next()
            .ok_or(InternalRequestError::OriginalPsbtNotBroadcastable)?;
        // Calculate the additional weight contribution
        let input_count = self.payjoin_psbt.inputs.len() - self.original_psbt.inputs.len();
        log::trace!("input_count : {}", input_count);
        let weight_per_input =
            input_pair.expected_input_weight().map_err(InternalRequestError::InputWeight)?;
        log::trace!("weight_per_input : {}", weight_per_input);
        let contribution_weight = weight_per_input * input_count as u64;
        log::trace!("contribution_weight: {}", contribution_weight);
        Ok(contribution_weight)
    }

    /// Calculate the additional output weight contributed by the receiver
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
        log::trace!("output_contribution_weight : {}", output_contribution_weight);
        output_contribution_weight
    }

    /// Return a Payjoin Proposal PSBT that the sender will find acceptable.
    ///
    /// This attempts to calculate any network fee owed by the receiver, subtract it from their output,
    /// and return a PSBT that can produce a consensus-valid transaction that the sender will accept.
    ///
    /// wallet_process_psbt should sign and finalize receiver inputs
    fn prepare_psbt(mut self, processed_psbt: Psbt) -> Result<PayjoinProposal, RequestError> {
        self.payjoin_psbt = processed_psbt;
        log::trace!("Preparing PSBT {:#?}", self.payjoin_psbt);
        for output in self.payjoin_psbt.outputs_mut() {
            output.bip32_derivation.clear();
            output.tap_key_origins.clear();
            output.tap_internal_key = None;
        }
        for input in self.payjoin_psbt.inputs_mut() {
            input.bip32_derivation.clear();
            input.tap_key_origins.clear();
            input.tap_internal_key = None;
            input.partial_sigs.clear();
        }
        for i in self.sender_input_indexes() {
            log::trace!("Clearing sender input {}", i);
            self.payjoin_psbt.inputs[i].non_witness_utxo = None;
            self.payjoin_psbt.inputs[i].witness_utxo = None;
            self.payjoin_psbt.inputs[i].final_script_sig = None;
            self.payjoin_psbt.inputs[i].final_script_witness = None;
            self.payjoin_psbt.inputs[i].tap_key_sig = None;
        }

        Ok(PayjoinProposal { payjoin_psbt: self.payjoin_psbt, params: self.params })
    }

    fn sender_input_indexes(&self) -> Vec<usize> {
        // iterate proposal as mutable WITH the outpoint (previous_output) available too
        let mut original_inputs = self.original_psbt.input_pairs().peekable();
        let mut sender_input_indexes = vec![];
        for (i, input) in self.payjoin_psbt.input_pairs().enumerate() {
            if let Some(original) = original_inputs.peek() {
                log::trace!(
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

    pub fn finalize_proposal(
        mut self,
        wallet_process_psbt: impl Fn(&Psbt) -> Result<Psbt, Error>,
        min_feerate_sat_per_vb: Option<FeeRate>,
        max_feerate_sat_per_vb: FeeRate,
    ) -> Result<PayjoinProposal, Error> {
        for i in self.sender_input_indexes() {
            log::trace!("Clearing sender script signatures for input {}", i);
            self.payjoin_psbt.inputs[i].final_script_sig = None;
            self.payjoin_psbt.inputs[i].final_script_witness = None;
            self.payjoin_psbt.inputs[i].tap_key_sig = None;
        }
        let psbt = self.apply_fee(min_feerate_sat_per_vb, max_feerate_sat_per_vb)?;
        let psbt = wallet_process_psbt(psbt)?;
        let payjoin_proposal = self.prepare_psbt(psbt)?;
        Ok(payjoin_proposal)
    }
}

/// A mutable checked proposal that the receiver may contribute inputs to to make a payjoin.
#[derive(Clone)]
pub struct PayjoinProposal {
    payjoin_psbt: Psbt,
    params: Params,
}

impl PayjoinProposal {
    pub fn utxos_to_be_locked(&self) -> impl '_ + Iterator<Item = &bitcoin::OutPoint> {
        self.payjoin_psbt.unsigned_tx.input.iter().map(|input| &input.previous_output)
    }

    pub fn is_output_substitution_disabled(&self) -> bool {
        self.params.disable_output_substitution
    }

    pub fn psbt(&self) -> &Psbt { &self.payjoin_psbt }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use bitcoin::hashes::Hash;
    use bitcoin::{Address, Network, ScriptBuf};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use super::*;

    struct MockHeaders {
        length: String,
    }

    impl MockHeaders {
        #[cfg(test)]
        fn new(length: u64) -> MockHeaders { MockHeaders { length: length.to_string() } }
    }

    impl Headers for MockHeaders {
        fn get_header(&self, key: &str) -> Option<&str> {
            match key {
                "content-length" => Some(&self.length),
                "content-type" => Some("text/plain"),
                _ => None,
            }
        }
    }

    fn proposal_from_test_vector() -> Result<UncheckedProposal, RequestError> {
        // OriginalPSBT Test Vector from BIP
        // | InputScriptType | Orginal PSBT Fee rate | maxadditionalfeecontribution | additionalfeeoutputindex|
        // |-----------------|-----------------------|------------------------------|-------------------------|
        // | P2SH-P2WPKH     |  2 sat/vbyte          | 0.00000182                   | 0                       |
        let original_psbt = "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";

        let body = original_psbt.as_bytes();
        let headers = MockHeaders::new(body.len() as u64);
        UncheckedProposal::from_request(
            body,
            "maxadditionalfeecontribution=182&additionalfeeoutputindex=0",
            headers,
        )
    }

    #[test]
    fn can_get_proposal_from_request() {
        let proposal = proposal_from_test_vector();
        assert!(proposal.is_ok(), "OriginalPSBT should be a valid request");
    }

    #[test]
    fn unchecked_proposal_unlocks_after_checks() {
        let proposal = proposal_from_test_vector().unwrap();
        assert_eq!(proposal.psbt_fee_rate().unwrap().to_sat_per_vb_floor(), 2);
        let mut payjoin = proposal
            .assume_interactive_receiver()
            .check_inputs_not_owned(|_| Ok(false))
            .expect("No inputs should be owned")
            .check_no_mixed_input_scripts()
            .expect("No mixed input scripts")
            .check_no_inputs_seen_before(|_| Ok(false))
            .expect("No inputs should be seen before")
            .identify_receiver_outputs(|script| {
                let network = Network::Bitcoin;
                Ok(Address::from_script(script, network).unwrap()
                    == Address::from_str(&"3CZZi7aWFugaCdUCS15dgrUUViupmB8bVM")
                        .unwrap()
                        .require_network(network)
                        .unwrap())
            })
            .expect("Receiver output should be identified")
            .commit_outputs()
            .commit_inputs();

        let payjoin = payjoin.apply_fee(None, FeeRate::ZERO);

        assert!(payjoin.is_ok(), "Payjoin should be a valid PSBT");
    }

    #[test]
    fn sender_specifies_excessive_feerate() {
        let mut proposal = proposal_from_test_vector().unwrap();
        assert_eq!(proposal.psbt_fee_rate().unwrap().to_sat_per_vb_floor(), 2);
        // Specify excessive fee rate in sender params
        proposal.params.min_feerate = FeeRate::from_sat_per_vb_unchecked(1000);
        // Input contribution for the receiver, from the BIP78 test vector
        let input: (OutPoint, TxOut) = (
            OutPoint {
                txid: "833b085de288cda6ff614c6e8655f61e7ae4f84604a2751998dc25a0d1ba278f"
                    .parse()
                    .unwrap(),
                vout: 1,
            },
            TxOut {
                value: Amount::from_sat(2000000),
                // HACK: The script pubkey in the original test vector is a nested p2sh witness
                // script, which is not correctly supported in our current weight calculations.
                // To get around this limitation, this test uses a native segwit script instead.
                script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::hash(
                    "00145f806655e5924c9204c2d51be5394f4bf9eda210".as_bytes(),
                )),
            },
        );
        let mut payjoin = proposal
            .assume_interactive_receiver()
            .check_inputs_not_owned(|_| Ok(false))
            .expect("No inputs should be owned")
            .check_no_mixed_input_scripts()
            .expect("No mixed input scripts")
            .check_no_inputs_seen_before(|_| Ok(false))
            .expect("No inputs should be seen before")
            .identify_receiver_outputs(|script| {
                let network = Network::Bitcoin;
                Ok(Address::from_script(script, network).unwrap()
                    == Address::from_str(&"3CZZi7aWFugaCdUCS15dgrUUViupmB8bVM")
                        .unwrap()
                        .require_network(network)
                        .unwrap())
            })
            .expect("Receiver output should be identified")
            .commit_outputs()
            .contribute_witness_inputs(vec![input])
            .expect("Failed to contribute inputs")
            .commit_inputs();
        let mut payjoin_clone = payjoin.clone();
        let psbt = payjoin.apply_fee(None, FeeRate::from_sat_per_vb_unchecked(1000));
        assert!(psbt.is_ok(), "Payjoin should be a valid PSBT");
        let psbt = payjoin_clone.apply_fee(None, FeeRate::from_sat_per_vb_unchecked(995));
        assert!(psbt.is_err(), "Payjoin exceeds receiver fee preference and should error");
    }

    #[test]
    fn additional_input_weight_matches_known_weight() {
        // All expected input weights pulled from:
        // https://bitcoin.stackexchange.com/questions/84004/how-do-virtual-size-stripped-size-and-raw-size-compare-between-legacy-address-f#84006
        // Input weight for a single P2PKH (legacy) receiver input
        let p2pkh_proposal = ProvisionalProposal {
            original_psbt: Psbt::from_str("cHNidP8BAHECAAAAAb2qhegy47hqffxh/UH5Qjd/G3sBH6cW2QSXZ86nbY3nAAAAAAD9////AhXKBSoBAAAAFgAU4TiLFD14YbpddFVrZa3+Zmz96yQQJwAAAAAAABYAFB4zA2o+5MsNRT/j+0twLi5VbwO9AAAAAAABAIcCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wMBSgD/////AgDyBSoBAAAAGXapFGUxpU6cGldVpjUm9rV2B+jTlphDiKwAAAAAAAAAACZqJKohqe3i9hw/cdHe/T+pmd+jaVN1XGkGiXmZYrSL69g2l06M+QAAAAABB2pHMEQCIGsOxO/bBv20bd68sBnEU3cxHR8OxEcUroL3ENhhjtN3AiB+9yWuBGKXu41hcfO4KP7IyLLEYc6j8hGowmAlCPCMPAEhA6WNSN4CqJ9F+42YKPlIFN0wJw7qawWbdelGRMkAbBRnACICAsdIAjsfMLKgfL2J9rfIa8yKdO1BOpSGRIFbFMBdTsc9GE4roNNUAACAAQAAgAAAAIABAAAAAAAAAAAA").unwrap(),
            payjoin_psbt: Psbt::from_str("cHNidP8BAJoCAAAAAtTRxwAtk38fRMP3ffdKkIi5r+Ss9AjaO8qEv+eQ/ho3AAAAAAD9////vaqF6DLjuGp9/GH9QflCN38bewEfpxbZBJdnzqdtjecAAAAAAP3///8CgckFKgEAAAAWABThOIsUPXhhul10VWtlrf5mbP3rJBAZBioBAAAAFgAUiDIby0wSbj1kv3MlvwoEKw3vNZUAAAAAAAEAhwIAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AwFoAP////8CAPIFKgEAAAAZdqkUPXhu3I6D9R0wUpvTvvUm+VGNcNuIrAAAAAAAAAAAJmokqiGp7eL2HD9x0d79P6mZ36NpU3VcaQaJeZlitIvr2DaXToz5AAAAAAEBIgDyBSoBAAAAGXapFD14btyOg/UdMFKb0771JvlRjXDbiKwBB2pHMEQCIGzKy8QfhHoAY0+LZCpQ7ZOjyyXqaSBnr89hH3Eg/xsGAiB3n8hPRuXCX/iWtURfXoJNUFu3sLeQVFf1dDFCZPN0dAEhA8rTfrwcq6dEBSNOrUfNb8+dm7q77vCtfdOmWx0HfajRAAEAhwIAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AwFKAP////8CAPIFKgEAAAAZdqkUZTGlTpwaV1WmNSb2tXYH6NOWmEOIrAAAAAAAAAAAJmokqiGp7eL2HD9x0d79P6mZ36NpU3VcaQaJeZlitIvr2DaXToz5AAAAAAAAAA==").unwrap(),
            params: Params::default(),
            change_vout: 0
        };
        assert_eq!(
            p2pkh_proposal.additional_input_weight().expect("should calculate input weight"),
            Weight::from_wu(592)
        );

        // Input weight for a single nested P2WPKH (nested segwit) receiver input
        let nested_p2wpkh_proposal = ProvisionalProposal {
            original_psbt: Psbt::from_str("cHNidP8BAHECAAAAAX57euL5j6xOst5JB/e/gp58RihmmpxXpsc2hEKKcVFkAAAAAAD9////AhAnAAAAAAAAFgAUtjrU62JOASAnPQ4e30wBM/Exk7ZM0QKVAAAAABYAFL6xh6gjSHmznJnPMbolG7wbGuwtAAAAAAABAIYCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wQCqgAA/////wIA+QKVAAAAABepFOyefe4gjXozL4pzi5vcPrjMeCJwhwAAAAAAAAAAJmokqiGp7eL2HD9x0d79P6mZ36NpU3VcaQaJeZlitIvr2DaXToz5AAAAAAEBIAD5ApUAAAAAF6kU7J597iCNejMvinOLm9w+uMx4InCHAQcXFgAUd6fhKfAd+JIJGpIGkMfMpjd/26sBCGsCRzBEAiBaCDgIrTw5bB1VZrB8RPycgKGNPw/YS6P+psUyxOUwgwIgbJkcbHlMoZxG7vBOVWnQQWayDTSvub6L20dDo1R5SS8BIQK2GCTydo2dJXC6C5wcSKzQ2pCsSygXa0+cMlJrRRnKtwAAIgIC0VgJvaoW2/lbq5atJhxfcgVzs6/gnpafsJHbz+ei484YDOqFk1QAAIABAACAAAAAgAEAAAACAAAAAA==").unwrap(),
            payjoin_psbt: Psbt::from_str("cHNidP8BAJoCAAAAAn57euL5j6xOst5JB/e/gp58RihmmpxXpsc2hEKKcVFkAAAAAAD9////VinByqmVDo3wPNB9LnNELJoJ0g+hOdWiTSXzWEUVtiAAAAAAAP3///8CEBkGKgEAAAAWABSZUDn7eqenP01ziWRBnTCrpwwD6vHQApUAAAAAFgAUvrGHqCNIebOcmc8xuiUbvBsa7C0AAAAAAAEAhgIAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////BAKqAAD/////AgD5ApUAAAAAF6kU7J597iCNejMvinOLm9w+uMx4InCHAAAAAAAAAAAmaiSqIant4vYcP3HR3v0/qZnfo2lTdVxpBol5mWK0i+vYNpdOjPkAAAAAAQEgAPkClQAAAAAXqRTsnn3uII16My+Kc4ub3D64zHgicIcAAQCEAgAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP////8CYAD/////AgDyBSoBAAAAF6kUx/+ZHBBBZ+6E/US1N2Oe7IDItXiHAAAAAAAAAAAmaiSqIant4vYcP3HR3v0/qZnfo2lTdVxpBol5mWK0i+vYNpdOjPkAAAAAAQEgAPIFKgEAAAAXqRTH/5kcEEFn7oT9RLU3Y57sgMi1eIcBBxcWABRDVkPBhZHK7tVQqp2uWqQC/GGTCgEIawJHMEQCIEv8/8VpUz0dK4MCcVzS7zoyt+hPRvWwLskZBuaurnFiAiBIuyt1IRaHqFSspDbjDNM607nrDQz4lmDnekNqMNn07AEhAp1Ol7vKvG2Oi8RSrsb7uSPTET83/YXuknx63PhfCG/zAAAA").unwrap(),
            params: Params::default(),
            change_vout: 0
        };
        // Currently nested segwit is not supported, see https://github.com/payjoin/rust-payjoin/issues/358
        assert!(nested_p2wpkh_proposal.additional_input_weight().is_err());

        // Input weight for a single P2WPKH (native segwit) receiver input
        let p2wpkh_proposal = ProvisionalProposal {
            original_psbt: Psbt::from_str("cHNidP8BAHECAAAAASom13OiXZIr3bKk+LtUndZJYqdHQQU8dMs1FZ93IctIAAAAAAD9////AmPKBSoBAAAAFgAU6H98YM9NE1laARQ/t9/90nFraf4QJwAAAAAAABYAFBPJFmYuJBsrIaBBp9ur98pMSKxhAAAAAAABAIQCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wMBWwD/////AgDyBSoBAAAAFgAUjTJXmC73n+URSNdfgbS6Oa6JyQYAAAAAAAAAACZqJKohqe3i9hw/cdHe/T+pmd+jaVN1XGkGiXmZYrSL69g2l06M+QAAAAABAR8A8gUqAQAAABYAFI0yV5gu95/lEUjXX4G0ujmuickGAQhrAkcwRAIgUqbHS0difIGTRwN56z2/EiqLQFWerfJspyjuwsGSCXcCIA3IRTu8FVgniU5E4gecAMeegVnlTbTVfFyusWhQ2kVVASEDChVRm26KidHNWLdCLBTq5jspGJr+AJyyMqmUkvPkwFsAIgIDeBqmRB3ESjFWIp+wUXn/adGZU3kqWGjdkcnKpk8bAyUY94v8N1QAAIABAACAAAAAgAEAAAAAAAAAAAA=").unwrap(),
            payjoin_psbt: Psbt::from_str("cHNidP8BAJoCAAAAAiom13OiXZIr3bKk+LtUndZJYqdHQQU8dMs1FZ93IctIAAAAAAD9////NG21aH8Vat3thaVmPvWDV/lvRmymFHeePcfUjlyngHIAAAAAAP3///8CH8oFKgEAAAAWABTof3xgz00TWVoBFD+33/3ScWtp/hAZBioBAAAAFgAU1mbnqky3bMxfmm0OgFaQCAs5fsoAAAAAAAEAhAIAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AwFbAP////8CAPIFKgEAAAAWABSNMleYLvef5RFI11+BtLo5ronJBgAAAAAAAAAAJmokqiGp7eL2HD9x0d79P6mZ36NpU3VcaQaJeZlitIvr2DaXToz5AAAAAAEBHwDyBSoBAAAAFgAUjTJXmC73n+URSNdfgbS6Oa6JyQYAAQCEAgAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP////8DAWcA/////wIA8gUqAQAAABYAFJFtkfHTt3y1EDMaN6CFjjNWtpCRAAAAAAAAAAAmaiSqIant4vYcP3HR3v0/qZnfo2lTdVxpBol5mWK0i+vYNpdOjPkAAAAAAQEfAPIFKgEAAAAWABSRbZHx07d8tRAzGjeghY4zVraQkQEIawJHMEQCIDTC49IB9AnItqd8zy5RDc05f2ApBAfJ5x4zYfj3bsD2AiAQvvSt5ipScHcUwdlYB9vFnEi68hmh55M5a5e+oWvxMAEhAqErVSVulFb97/r5KQryOS1Xgghff8R7AOuEnvnmslQ5AAAA").unwrap(),
            params: Params::default(),
            change_vout: 0
        };
        assert_eq!(
            p2wpkh_proposal.additional_input_weight().expect("should calculate input weight"),
            Weight::from_wu(272)
        );

        // Input weight for a single P2TR (taproot) receiver input
        let p2tr_proposal = ProvisionalProposal {
            original_psbt: Psbt::from_str("cHNidP8BAHECAAAAAU/CHxd1oi9Lq1xOD2GnHe0hsQdGJ2mkpYkmeasTj+w1AAAAAAD9////Am3KBSoBAAAAFgAUqJL/PDPnHeihhNhukTz8QEdZbZAQJwAAAAAAABYAFInyO0NQF7YR22Sm0YTPGm6yf19YAAAAAAABASsA8gUqAQAAACJRIGOPekNKFs9ASLj3FdlCLiou/jdPUegJGzlA111A80MAAQhCAUC3zX8eSeL8+bAo6xO0cpon83UsJdttiuwfMn/pBwub82rzMsoS6HZNXzg7hfcB3p1uj8JmqsBkZwm8k6fnU2peACICA+u+FjwmhEgWdjhEQbO49D0NG8iCYUoqhlfsj0LN7hiRGOcVI65UAACAAQAAgAAAAIABAAAAAAAAAAAA").unwrap(),
            payjoin_psbt: Psbt::from_str("cHNidP8BAJoCAAAAAk/CHxd1oi9Lq1xOD2GnHe0hsQdGJ2mkpYkmeasTj+w1AAAAAAD9////Fz+ELsYp/55j6+Jl2unG9sGvpHTiSyzSORBvtu1GEB4AAAAAAP3///8CM8oFKgEAAAAWABSokv88M+cd6KGE2G6RPPxAR1ltkBAZBioBAAAAFgAU68J5imRcKy3g5JCT3bEoP9IXEn0AAAAAAAEBKwDyBSoBAAAAIlEgY496Q0oWz0BIuPcV2UIuKi7+N09R6AkbOUDXXUDzQwAAAQErAPIFKgEAAAAiUSCfbbX+FHJbzC71eEFLsMjDouMJbu8ogeR0eNoNxMM9CwEIQwFBeyOLUebV/YwpaLTpLIaTXaSiPS7Dn6o39X4nlUzQLfb6YyvCAsLA5GTxo+Zb0NUINZ8DaRyUWknOpU/Jzuwn2gEAAAA=").unwrap(),
            params: Params::default(),
            change_vout: 0
        };
        assert_eq!(
            p2tr_proposal.additional_input_weight().expect("should calculate input weight"),
            Weight::from_wu(230)
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
