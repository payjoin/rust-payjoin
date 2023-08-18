//! Send a Payjoin
//!
//! This module contains types and methods used to implement sending via [BIP 78 Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki).
//! Usage is pretty simple:
//!
//! 1. Parse BIP21 as [`payjoin::Uri`](crate::Uri)
//! 2. Construct URI request parameters, a finalized “Original PSBT” paying .amount to .address
//! 3. (optional) Spawn a thread or async task that will broadcast the original PSBT fallback after delay (e.g. 1 minute) unless canceled
//! 4. Construct the request using [`RequestBuilder`](crate::send::RequestBuilder) with the PSBT and payjoin uri
//! 5. Send the request and receive response
//! 6. Process the response with [`Context::process_response()`](crate::send::Context::process_response())
//! 7. Sign and finalize the Payjoin Proposal PSBT
//! 8. Broadcast the Payjoin Transaction (and cancel the optional fallback broadcast)
//!
//! This crate is runtime-agnostic. Data persistence, chain interactions, and networking may be provided by custom implementations or copy the reference [`payjoin-cli`](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-cli) for bitcoind, [`nolooking`](https://github.com/chaincase-app/nolooking) for LND, or [`bitmask-core`](https://github.com/diba-io/bitmask-core) BDK integration. Bring your own wallet and http client.
//!
//! ## Send a Payjoin
//!
//! The `sender` feature provides the check methods and PSBT data manipulation necessary to send payjoins. Just connect your wallet and an HTTP client. The reference implementation uses [`reqwest`](https://docs.rs/reqwest/latest/reqwest/) and Bitcoin Core RPC.
//!
//! ### 1. Parse BIP21 as [`payjoin::Uri`](crate::Uri)
//!
//! Start by parsing a valid BIP 21 uri having the `pj` parameter. This is the [`bip21`](https://crates.io/crates/bip21) crate under the hood.
//!
//! ```
//! let uri = payjoin::Uri::try_from(bip21)
//!     .map_err(|e| anyhow!("Failed to create URI from BIP21: {}", e))?
//!     .assume_checked(); // assume bitcoin address is for the right network
//! ```
//!
//! ### 2. Construct URI request parameters, a finalized "Original PSBT" paying `.amount` to `.address`
//!
//! ```
//! let mut outputs = HashMap::with_capacity(1);
//! outputs.insert(uri.address.to_string(), amount);
//!
//! let options = bitcoincore_rpc::json::WalletCreateFundedPsbtOptions {
//!     lock_unspent: Some(true),
//!     fee_rate: Some(Amount::from_sat(2000)), // SPECIFY YOUR USER'S FEE RATE
//!     ..Default::default()
//! };
//! // in payjoin-cli, bitcoind is set up as a client from the config file
//! let psbt = bitcoind
//!     .wallet_create_funded_psbt(
//!         &[], // inputs
//!         &outputs,
//!         None, // locktime
//!         Some(options),
//!         None,
//!     )
//!     .context("Failed to create PSBT")?
//!     .psbt;
//! let psbt = bitcoind
//!     .wallet_process_psbt(&psbt, None, None, None)
//!     .with_context(|| "Failed to process PSBT")?
//!     .psbt;
//! let psbt = Psbt::from_str(&psbt) // SHOULD BE PROVIDED BY CRATE AS HELPER USING rust-bitcoin base64 feature
//!     .with_context(|| "Failed to load PSBT from base64")?;
//! log::debug!("Original psbt: {:#?}", psbt);
//! ```
//!
//! ### 3. (optional) Spawn a thread or async task that will broadcast the transaction after delay (e.g. 1 minute) unless canceled
//!
//! This was written in the original docs, but it should be clarified: In case the payjoin goes through but you still want to pay by default. This is missing from the `payjoin-cli`.
//!
//! Writing this, I think of [Signal's contributing guidelines](https://github.com/signalapp/Signal-iOS/blob/main/CONTRIBUTING.md#development-ideology):
//! > "The answer is not more options. If you feel compelled to add a preference that's exposed to the user, it's very possible you've made a wrong turn somewhere."
//!
//! ### 4. Construct the request with the PSBT and parameters
//!
//! ```
//! let min_fee_rate = bitcoin::FeeRate::from_sat_per_vb(1); // SPECIFY YOUR USER'S MINIMUM FEE RATE
//! let (req, ctx) = RequestBuilder::from_psbt_and_uri(psbt, uri)
//!     .with_context(|| "Failed to create payjoin request")?
//!     .build_recommended(min_fee_rate)
//!     .with_context(|| "Failed to create payjoin request")?;
//! ```
//!
//! ### 5. Send the request and receive response
//!
//! Senders request a payjoin from the receiver with a payload containing the Original PSBT  and optional parameters. They require a secure endpoint for authentication and message secrecy to prevent that transaction from being modified by a malicious third party during transit or being snooped on. Only https and .onion endpoints are spec-compatible payjoin endpoints.
//!
//! Avoiding the secure endpoint requirement is convenient for testing.
//!
//! ```
//! let client = reqwest::blocking::Client::builder()
//!     .build()
//!     .with_context(|| "Failed to build reqwest http client")?;
//! let response = client
//!     .post(req.url)
//!     .body(req.body)
//!     .header("Content-Type", "text/plain")
//!     .send()
//!     .with_context(|| "HTTP request failed")?;
//! ```
//!
//! ### 6. Process the response
//!
//! An `Ok` response should include a Payjoin Proposal PSBT. Check that it's signed, following protocol, not trying to steal or otherwise error.
//!
//! ```
//! // TODO display well-known errors and log::debug the rest
//! // ctx is the context returned from create_pj_request in step 4.
//! let psbt = ctx.process_response(response).with_context(|| "Failed to process response")?;
//! log::debug!("Proposed psbt: {:#?}", psbt);
//! ```
//!
//! Payjoin response errors (called [receiver's errors in spec](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#receivers-well-known-errors)) come from a remote server and can be used "maliciously to phish a non technical user." Only those "well-known" errors according to spec should be displayed with preset messages to prevent phishing.
//!
//! ### 7. Sign and finalize the Payjoin Proposal PSBT
//!
//! Most software can handle adding the last signatures to a PSBT without issue.
//!
//! ```
//! let psbt = bitcoind
//!     .wallet_process_psbt(&serialize_psbt(&psbt), None, None, None)
//!     .with_context(|| "Failed to process PSBT")?
//!     .psbt;
//! let tx = bitcoind
//!     .finalize_psbt(&psbt, Some(true))
//!     .with_context(|| "Failed to finalize PSBT")?
//!     .hex
//!     .ok_or_else(|| anyhow!("Incomplete PSBT"))?;
//! ```
//!
//! ### 8. Broadcast the Payjoin Transaction
//!
//! In order to preserve privacy between the transaction and the IP address from which it originates, transaction broadcasting should be done using Tor, a VPN, or proxy.
//!
//! ```
//! let txid =
//!     bitcoind.send_raw_transaction(&tx).with_context(|| "Failed to send raw transaction")?;
//! log::info!("Transaction sent: {}", txid);
//! ```
//!
//! 📤 Sending payjoin is just that simple.

use std::str::FromStr;

use bitcoin::address::NetworkChecked;
use bitcoin::psbt::Psbt;
use bitcoin::{FeeRate, Script, ScriptBuf, Sequence, TxOut, Weight};
pub use error::{CreateRequestError, ValidationError};
pub(crate) use error::{InternalCreateRequestError, InternalValidationError};
use url::Url;

use crate::input_type::InputType;
use crate::psbt::PsbtExt;
use crate::uri::UriExt;
use crate::weight::{varint_size, ComputeWeight};
use crate::PjUri;

// See usize casts
#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
compile_error!("This crate currently only supports 32 bit and 64 bit architectures");

mod error;

type InternalResult<T> = Result<T, InternalValidationError>;

pub struct RequestBuilder<'a> {
    psbt: Psbt,
    uri: PjUri<'a>,
    disable_output_substitution: bool,
    fee_contribution: Option<(bitcoin::Amount, Option<usize>)>,
    clamp_fee_contribution: bool,
    min_fee_rate: FeeRate,
}

impl<'a> RequestBuilder<'a> {
    /// Prepare an HTTP request and request context to process the response
    ///
    /// An HTTP client will own the Request data while Context sticks around so
    /// a `(Request, Context)` tuple is returned from `RequestBuilder::build()`
    /// to keep them separated.
    pub fn from_psbt_and_uri(
        psbt: Psbt,
        uri: crate::Uri<'a, NetworkChecked>,
    ) -> Result<Self, CreateRequestError> {
        let uri = uri
            .check_pj_supported()
            .map_err(|_| InternalCreateRequestError::UriDoesNotSupportPayjoin)?;
        Ok(Self {
            psbt,
            uri,
            // Sender's optional parameters
            disable_output_substitution: false,
            fee_contribution: None,
            clamp_fee_contribution: false,
            min_fee_rate: FeeRate::ZERO,
        })
    }

    /// Disable output substitution even if the receiver didn't.
    ///
    /// This forbids receiver switching output or decreasing amount.
    /// It is generally **not** recommended to set this as it may prevent the receiver from
    /// doing advanced operations such as opening LN channels and it also guarantees the
    /// receiver will **not** reward the sender with a discount.
    pub fn always_disable_output_substitution(mut self, disable: bool) -> Self {
        self.disable_output_substitution = disable;
        self
    }

    // Calculate the recommended fee contribution for an Original PSBT.
    //
    // BIP 78 recommends contributing `originalPSBTFeeRate * vsize(sender_input_type)`.
    // The minfeerate parameter is set if the contribution is available in change.
    //
    // This method fails if no recommendation can be made or if the PSBT is malformed.
    pub fn build_recommended(
        self,
        min_fee_rate: FeeRate,
    ) -> Result<(Request, Context), CreateRequestError> {
        // TODO support optional batched payout scripts. This would require a change to
        // build() which now checks for a single payee.
        let mut payout_scripts = std::iter::once(self.uri.address.script_pubkey());
        if let Some((additional_fee_index, fee_available)) = self
            .psbt
            .unsigned_tx
            .output
            .clone()
            .into_iter()
            .enumerate()
            .find(|(_, txo)| payout_scripts.all(|script| script != txo.script_pubkey))
            .map(|(i, txo)| (i, bitcoin::Amount::from_sat(txo.value)))
        {
            let input_types = self
                .psbt
                .input_pairs()
                .map(|input| {
                    let txo =
                        input.previous_txout().map_err(InternalCreateRequestError::PrevTxOut)?;
                    Ok(InputType::from_spent_input(txo, input.psbtin)
                        .map_err(InternalCreateRequestError::InputType)?)
                })
                .collect::<Result<Vec<InputType>, InternalCreateRequestError>>()?;

            let first_type = input_types.first().ok_or(InternalCreateRequestError::NoInputs)?;
            // use cheapest default if mixed input types
            let mut input_vsize = InputType::Taproot.expected_input_weight();
            // Check if all inputs are the same type
            if input_types.iter().all(|input_type| input_type == first_type) {
                input_vsize = first_type.expected_input_weight();
            }

            let recommended_additional_fee = min_fee_rate * input_vsize;
            if fee_available < recommended_additional_fee {
                log::warn!("Insufficient funds to maintain specified minimum feerate.");
                return self.build_with_additional_fee(
                    fee_available,
                    Some(additional_fee_index),
                    min_fee_rate,
                    true,
                );
            }
            return self.build_with_additional_fee(
                recommended_additional_fee,
                Some(additional_fee_index),
                min_fee_rate,
                false,
            );
        }
        self.build_non_incentivizing()
    }

    /// Offer the receiver contribution to pay for his input.
    ///
    /// These parameters will allow the receiver to take `max_fee_contribution` from given change
    /// output to pay for additional inputs. The recommended fee is `size_of_one_input * fee_rate`.
    ///
    /// `change_index` specifies which output can be used to pay fee. If `None` is provided, then
    /// the output is auto-detected unless the supplied transaction has more than two outputs.
    ///
    /// `clamp_fee_contribution` decreases fee contribution instead of erroring.
    ///
    /// If this option is true and a transaction with change amount lower than fee
    /// contribution is provided then instead of returning error the fee contribution will
    /// be just lowered in the request to match the change amount.
    pub fn build_with_additional_fee(
        mut self,
        max_fee_contribution: bitcoin::Amount,
        change_index: Option<usize>,
        min_fee_rate: FeeRate,
        clamp_fee_contribution: bool,
    ) -> Result<(Request, Context), CreateRequestError> {
        self.fee_contribution = Some((max_fee_contribution, change_index));
        self.clamp_fee_contribution = clamp_fee_contribution;
        self.min_fee_rate = min_fee_rate;
        self.build()
    }

    /// Perform Payjoin without incentivizing the payee to cooperate.
    ///
    /// While it's generally better to offer some contribution some users may wish not to.
    /// This function disables contribution.
    pub fn build_non_incentivizing(mut self) -> Result<(Request, Context), CreateRequestError> {
        // since this is a builder, these should already be cleared
        // but we'll reset them to be sure
        self.fee_contribution = None;
        self.clamp_fee_contribution = false;
        self.min_fee_rate = FeeRate::ZERO;
        self.build()
    }

    fn build(self) -> Result<(Request, Context), CreateRequestError> {
        let mut psbt =
            self.psbt.validate().map_err(InternalCreateRequestError::InconsistentOriginalPsbt)?;
        psbt.validate_input_utxos(true)
            .map_err(InternalCreateRequestError::InvalidOriginalInput)?;
        let disable_output_substitution =
            self.uri.extras.disable_output_substitution || self.disable_output_substitution;
        let payee = self.uri.address.script_pubkey();

        check_single_payee(&psbt, &payee, self.uri.amount)?;
        let fee_contribution = determine_fee_contribution(
            &psbt,
            &payee,
            self.fee_contribution,
            self.clamp_fee_contribution,
        )?;
        clear_unneeded_fields(&mut psbt);

        let zeroth_input = psbt.input_pairs().next().ok_or(InternalCreateRequestError::NoInputs)?;

        let sequence = zeroth_input.txin.sequence;
        let txout = zeroth_input.previous_txout().expect("We already checked this above");
        let input_type = InputType::from_spent_input(txout, zeroth_input.psbtin).unwrap();
        let url = serialize_url(
            self.uri.extras._endpoint.into(),
            disable_output_substitution,
            fee_contribution,
            self.min_fee_rate,
        )
        .map_err(InternalCreateRequestError::Url)?;
        let body = serialize_psbt(&psbt);
        Ok((
            Request { url, body },
            Context {
                original_psbt: psbt,
                disable_output_substitution,
                fee_contribution,
                payee,
                input_type,
                sequence,
                min_fee_rate: self.min_fee_rate,
            },
        ))
    }
}

/// Represents data that needs to be transmitted to the receiver.
///
/// You need to send this request over HTTP(S) to the receiver.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Request {
    /// URL to send the request to.
    ///
    /// This is full URL with scheme etc - you can pass it right to `reqwest` or a similar library.
    pub url: Url,

    /// Bytes to be sent to the receiver.
    ///
    /// This is properly encoded PSBT, already in base64. You only need to make sure `Content-Type`
    /// is `text/plain` and `Content-Length` is `body.len()` (most libraries do the latter
    /// automatically).
    pub body: Vec<u8>,
}

/// Data required for validation of response.
///
/// This type is used to process the response. Get it from [`RequestBuilder`](crate::send::RequestBuilder)'s build methods.
/// Then you only need to call [`.process_response()`](crate::send::Context::process_response()) on it to continue BIP78 flow.
pub struct Context {
    original_psbt: Psbt,
    disable_output_substitution: bool,
    fee_contribution: Option<(bitcoin::Amount, usize)>,
    min_fee_rate: FeeRate,
    input_type: InputType,
    sequence: Sequence,
    payee: ScriptBuf,
}

macro_rules! check_eq {
    ($proposed:expr, $original:expr, $error:ident) => {
        match ($proposed, $original) {
            (proposed, original) if proposed != original =>
                return Err(InternalValidationError::$error { proposed, original }),
            _ => (),
        }
    };
}

macro_rules! ensure {
    ($cond:expr, $error:ident) => {
        if !($cond) {
            return Err(InternalValidationError::$error);
        }
    };
}

impl Context {
    /// Decodes and validates the response.
    ///
    /// Call this method with response from receiver to continue BIP78 flow. If the response is
    /// valid you will get appropriate PSBT that you should sign and broadcast.
    #[inline]
    pub fn process_response(
        self,
        response: &mut impl std::io::Read,
    ) -> Result<Psbt, ValidationError> {
        let mut res_str = String::new();
        response.read_to_string(&mut res_str).map_err(InternalValidationError::Io)?;
        let proposal = Psbt::from_str(&res_str).map_err(InternalValidationError::Psbt)?;

        // process in non-generic function
        self.process_proposal(proposal).map(Into::into).map_err(Into::into)
    }

    fn process_proposal(self, proposal: Psbt) -> InternalResult<Psbt> {
        self.basic_checks(&proposal)?;
        let in_stats = self.check_inputs(&proposal)?;
        let out_stats = self.check_outputs(&proposal)?;
        self.check_fees(&proposal, in_stats, out_stats)?;
        Ok(proposal)
    }

    fn check_fees(
        &self,
        proposal: &Psbt,
        in_stats: InputStats,
        out_stats: OutputStats,
    ) -> InternalResult<()> {
        if out_stats.total_value > in_stats.total_value {
            return Err(InternalValidationError::Inflation);
        }
        let proposed_psbt_fee = in_stats.total_value - out_stats.total_value;
        let original_fee = self.original_psbt.calculate_fee();
        ensure!(original_fee <= proposed_psbt_fee, AbsoluteFeeDecreased);
        ensure!(
            out_stats.contributed_fee <= proposed_psbt_fee - original_fee,
            PayeeTookContributedFee
        );
        let original_weight = Weight::from_wu(u64::from(self.original_psbt.unsigned_tx.weight()));
        let original_fee_rate = original_fee / original_weight;
        ensure!(
            out_stats.contributed_fee
                <= original_fee_rate
                    * self.input_type.expected_input_weight()
                    * (proposal.inputs.len() - self.original_psbt.inputs.len()) as u64,
            FeeContributionPaysOutputSizeIncrease
        );
        if self.min_fee_rate > FeeRate::ZERO {
            let non_input_output_size =
                // version
                4 +
                // count variants
                varint_size(proposal.unsigned_tx.input.len() as u64) +
                varint_size(proposal.unsigned_tx.output.len() as u64) +
                // lock time
                4;
            let weight_without_witnesses =
                Weight::from_non_witness_data_size(non_input_output_size)
                    + in_stats.total_weight
                    + out_stats.total_weight;
            let total_weight = if in_stats.inputs_with_witnesses == 0 {
                weight_without_witnesses
            } else {
                weight_without_witnesses
                    + Weight::from_wu(
                        (proposal.unsigned_tx.input.len() - in_stats.inputs_with_witnesses + 2)
                            as u64,
                    )
            };
            ensure!(proposed_psbt_fee / total_weight >= self.min_fee_rate, FeeRateBelowMinimum);
        }
        Ok(())
    }

    // version and lock time
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

    fn check_inputs(&self, proposal: &Psbt) -> InternalResult<InputStats> {
        use crate::weight::ComputeSize;

        let mut original_inputs = self.original_psbt.input_pairs().peekable();
        let mut total_value = bitcoin::Amount::ZERO;
        let mut total_weight = Weight::ZERO;
        let mut inputs_with_witnesses = 0;

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
                        proposed.psbtin.non_witness_utxo.is_none(),
                        SenderTxinContainsNonWitnessUtxo
                    );
                    ensure!(proposed.psbtin.witness_utxo.is_none(), SenderTxinContainsWitnessUtxo);
                    ensure!(
                        proposed.psbtin.final_script_sig.is_none(),
                        SenderTxinContainsFinalScriptSig
                    );
                    ensure!(
                        proposed.psbtin.final_script_witness.is_none(),
                        SenderTxinContainsFinalScriptWitness
                    );
                    let prevout = original.previous_txout().expect("We've validated this before");
                    total_value += bitcoin::Amount::from_sat(prevout.value);
                    // We assume the signture will be the same size
                    // I know sigs can be slightly different size but there isn't much to do about
                    // it other than prefer Taproot.
                    total_weight += original.txin.weight();
                    if !original.txin.witness.is_empty() {
                        inputs_with_witnesses += 1;
                    }

                    original_inputs.next();
                }
                // theirs (receiver)
                None | Some(_) => {
                    // Verify the PSBT input is finalized
                    ensure!(
                        proposed.psbtin.final_script_sig.is_some()
                            || proposed.psbtin.final_script_witness.is_some(),
                        ReceiverTxinNotFinalized
                    );
                    if let Some(script_sig) = &proposed.psbtin.final_script_sig {
                        // The weight of the TxIn when it's included in a legacy transaction
                        // (i.e., a transaction having only legacy inputs).
                        total_weight += Weight::from_non_witness_data_size(
                            32 /* txid */ + 4 /* vout */ + 4 /* sequence */ + script_sig.encoded_size(),
                        );
                    }
                    if let Some(script_witness) = &proposed.psbtin.final_script_witness {
                        if !script_witness.is_empty() {
                            inputs_with_witnesses += 1;
                            total_weight += crate::weight::witness_weight(script_witness);
                        };
                    }

                    // Verify that non_witness_utxo or witness_utxo are filled in.
                    ensure!(
                        proposed.psbtin.witness_utxo.is_some()
                            || proposed.psbtin.non_witness_utxo.is_some(),
                        ReceiverTxinMissingUtxoInfo
                    );
                    ensure!(proposed.txin.sequence == self.sequence, MixedSequence);
                    let txout = proposed
                        .previous_txout()
                        .map_err(InternalValidationError::InvalidProposedInput)?;
                    total_value += bitcoin::Amount::from_sat(txout.value);
                    check_eq!(
                        InputType::from_spent_input(txout, proposed.psbtin)?,
                        self.input_type,
                        MixedInputTypes
                    );
                }
            }
        }
        ensure!(original_inputs.peek().is_none(), MissingOrShuffledInputs);
        Ok(InputStats { total_value, total_weight, inputs_with_witnesses })
    }

    fn check_outputs(&self, proposal: &Psbt) -> InternalResult<OutputStats> {
        let mut original_outputs = proposal.unsigned_tx.output.iter().enumerate().peekable();
        let mut total_value = bitcoin::Amount::ZERO;
        let mut contributed_fee = bitcoin::Amount::ZERO;
        let mut total_weight = Weight::ZERO;

        for (proposed_txout, proposed_psbtout) in
            proposal.unsigned_tx.output.iter().zip(&proposal.outputs)
        {
            ensure!(proposed_psbtout.bip32_derivation.is_empty(), TxOutContainsKeyPaths);
            total_value += bitcoin::Amount::from_sat(proposed_txout.value);
            total_weight += Weight::from_wu(proposed_txout.weight() as u64);
            match (original_outputs.peek(), self.fee_contribution) {
                // fee output
                (
                    Some((original_output_index, original_output)),
                    Some((max_fee_contrib, fee_contrib_idx)),
                ) if proposed_txout.script_pubkey == original_output.script_pubkey
                    && *original_output_index == fee_contrib_idx =>
                {
                    if proposed_txout.value < original_output.value {
                        contributed_fee =
                            bitcoin::Amount::from_sat(original_output.value - proposed_txout.value);
                        ensure!(contributed_fee < max_fee_contrib, FeeContributionExceedsMaximum);
                        //The remaining fee checks are done in the caller
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
                // all original outputs processed, only additional outputs remain
                _ => (),
            }
        }

        ensure!(original_outputs.peek().is_none(), MissingOrShuffledOutputs);
        Ok(OutputStats { total_value, contributed_fee, total_weight })
    }
}

struct OutputStats {
    total_value: bitcoin::Amount,
    contributed_fee: bitcoin::Amount,
    total_weight: Weight,
}

struct InputStats {
    total_value: bitcoin::Amount,
    total_weight: Weight,
    inputs_with_witnesses: usize,
}

fn check_single_payee(
    psbt: &Psbt,
    script_pubkey: &Script,
    amount: Option<bitcoin::Amount>,
) -> Result<(), InternalCreateRequestError> {
    let mut payee_found = false;
    for output in &psbt.unsigned_tx.output {
        if output.script_pubkey == *script_pubkey {
            if let Some(amount) = amount {
                if output.value != amount.to_sat() {
                    return Err(InternalCreateRequestError::PayeeValueNotEqual);
                }
            }
            if payee_found {
                return Err(InternalCreateRequestError::MultiplePayeeOutputs);
            }
            payee_found = true;
        }
    }
    if payee_found {
        Ok(())
    } else {
        Err(InternalCreateRequestError::MissingPayeeOutput)
    }
}

fn clear_unneeded_fields(psbt: &mut Psbt) {
    psbt.xpub_mut().clear();
    psbt.proprietary_mut().clear();
    psbt.unknown_mut().clear();
    for input in psbt.inputs_mut() {
        input.bip32_derivation.clear();
        input.proprietary.clear();
        input.unknown.clear();
    }
    for output in psbt.outputs_mut() {
        output.bip32_derivation.clear();
        output.proprietary.clear();
        output.unknown.clear();
    }
}

fn check_fee_output_amount(
    output: &TxOut,
    fee: bitcoin::Amount,
    clamp_fee_contribution: bool,
) -> Result<bitcoin::Amount, InternalCreateRequestError> {
    if output.value < fee.to_sat() {
        if clamp_fee_contribution {
            Ok(bitcoin::Amount::from_sat(output.value))
        } else {
            Err(InternalCreateRequestError::FeeOutputValueLowerThanFeeContribution)
        }
    } else {
        Ok(fee)
    }
}

fn find_change_index(
    psbt: &Psbt,
    payee: &Script,
    fee: bitcoin::Amount,
    clamp_fee_contribution: bool,
) -> Result<Option<(bitcoin::Amount, usize)>, InternalCreateRequestError> {
    match (psbt.unsigned_tx.output.len(), clamp_fee_contribution) {
        (0, _) => return Err(InternalCreateRequestError::NoOutputs),
        (1, false) if psbt.unsigned_tx.output[0].script_pubkey == *payee =>
            return Err(InternalCreateRequestError::FeeOutputValueLowerThanFeeContribution),
        (1, true) if psbt.unsigned_tx.output[0].script_pubkey == *payee => return Ok(None),
        (1, _) => return Err(InternalCreateRequestError::MissingPayeeOutput),
        (2, _) => (),
        _ => return Err(InternalCreateRequestError::AmbiguousChangeOutput),
    }
    let (index, output) = psbt
        .unsigned_tx
        .output
        .iter()
        .enumerate()
        .find(|(_, output)| output.script_pubkey != *payee)
        .ok_or(InternalCreateRequestError::MultiplePayeeOutputs)?;

    Ok(Some((check_fee_output_amount(output, fee, clamp_fee_contribution)?, index)))
}

fn check_change_index(
    psbt: &Psbt,
    payee: &Script,
    fee: bitcoin::Amount,
    index: usize,
    clamp_fee_contribution: bool,
) -> Result<(bitcoin::Amount, usize), InternalCreateRequestError> {
    let output = psbt
        .unsigned_tx
        .output
        .get(index)
        .ok_or(InternalCreateRequestError::ChangeIndexOutOfBounds)?;
    if output.script_pubkey == *payee {
        return Err(InternalCreateRequestError::ChangeIndexPointsAtPayee);
    }
    Ok((check_fee_output_amount(output, fee, clamp_fee_contribution)?, index))
}

fn determine_fee_contribution(
    psbt: &Psbt,
    payee: &Script,
    fee_contribution: Option<(bitcoin::Amount, Option<usize>)>,
    clamp_fee_contribution: bool,
) -> Result<Option<(bitcoin::Amount, usize)>, InternalCreateRequestError> {
    Ok(match fee_contribution {
        Some((fee, None)) => find_change_index(psbt, payee, fee, clamp_fee_contribution)?,
        Some((fee, Some(index))) =>
            Some(check_change_index(psbt, payee, fee, index, clamp_fee_contribution)?),
        None => None,
    })
}

fn serialize_url(
    endpoint: String,
    disable_output_substitution: bool,
    fee_contribution: Option<(bitcoin::Amount, usize)>,
    min_fee_rate: FeeRate,
) -> Result<Url, url::ParseError> {
    let mut url = Url::parse(&endpoint)?;
    url.query_pairs_mut().append_pair("v", "1");
    if disable_output_substitution {
        url.query_pairs_mut().append_pair("disableoutputsubstitution", "1");
    }
    if let Some((amount, index)) = fee_contribution {
        url.query_pairs_mut()
            .append_pair("additionalfeeoutputindex", &index.to_string())
            .append_pair("maxadditionalfeecontribution", &amount.to_sat().to_string());
    }
    if min_fee_rate > FeeRate::ZERO {
        // TODO serialize in rust-bitcoin <https://github.com/rust-bitcoin/rust-bitcoin/pull/1787/files#diff-c2ea40075e93ccd068673873166cfa3312ec7439d6bc5a4cbc03e972c7e045c4>
        let float_fee_rate = min_fee_rate.to_sat_per_kwu() as f32 / 250.0_f32;
        url.query_pairs_mut().append_pair("minfeerate", &float_fee_rate.to_string());
    }
    Ok(url)
}

fn serialize_psbt(psbt: &Psbt) -> Vec<u8> {
    let bytes = psbt.serialize();
    bitcoin::base64::encode(bytes).into_bytes()
}

#[cfg(test)]
mod tests {
    #[test]
    fn official_vectors() {
        use std::str::FromStr;

        use bitcoin::psbt::Psbt;
        use bitcoin::FeeRate;

        use crate::input_type::{InputType, SegWitV0Type};
        use crate::psbt::PsbtExt;

        let original_psbt = "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";

        let proposal = "cHNidP8BAJwCAAAAAo8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////jye60aAl3JgZdaIERvjkeh72VYZuTGH/ps2I4l0IO4MBAAAAAP7///8CJpW4BQAAAAAXqRQd6EnwadJ0FQ46/q6NcutaawlEMIcACT0AAAAAABepFHdAltvPSGdDwi9DR+m0af6+i2d6h9MAAAAAAQEgqBvXBQAAAAAXqRTeTh6QYcpZE1sDWtXm1HmQRUNU0IcBBBYAFMeKRXJTVYKNVlgHTdUmDV/LaYUwIgYDFZrAGqDVh1TEtNi300ntHt/PCzYrT2tVEGcjooWPhRYYSFzWUDEAAIABAACAAAAAgAEAAAAAAAAAAAEBIICEHgAAAAAAF6kUyPLL+cphRyyI5GTUazV0hF2R2NWHAQcXFgAUX4BmVeWSTJIEwtUb5TlPS/ntohABCGsCRzBEAiBnu3tA3yWlT0WBClsXXS9j69Bt+waCs9JcjWtNjtv7VgIge2VYAaBeLPDB6HGFlpqOENXMldsJezF9Gs5amvDQRDQBIQJl1jz1tBt8hNx2owTm+4Du4isx0pmdKNMNIjjaMHFfrQABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUIgICygvBWB5prpfx61y1HDAwo37kYP3YRJBvAjtunBAur3wYSFzWUDEAAIABAACAAAAAgAEAAAABAAAAAAA=";

        let original_psbt = Psbt::from_str(original_psbt).unwrap();
        eprintln!("original: {:#?}", original_psbt);
        let payee = original_psbt.unsigned_tx.output[1].script_pubkey.clone();
        let sequence = original_psbt.unsigned_tx.input[0].sequence;
        let ctx = super::Context {
            original_psbt,
            disable_output_substitution: false,
            fee_contribution: None,
            min_fee_rate: FeeRate::ZERO,
            payee,
            input_type: InputType::SegWitV0 { ty: SegWitV0Type::Pubkey, nested: true },
            sequence,
        };
        let mut proposal = Psbt::from_str(proposal).unwrap();
        eprintln!("proposal: {:#?}", proposal);
        for output in proposal.outputs_mut() {
            output.bip32_derivation.clear();
        }
        for input in proposal.inputs_mut() {
            input.bip32_derivation.clear();
        }
        proposal.inputs_mut()[0].witness_utxo = None;
        ctx.process_proposal(proposal).unwrap();
    }
}
