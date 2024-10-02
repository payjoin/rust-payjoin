//! Send a Payjoin
//!
//! This module contains types and methods used to implement sending via [BIP 78
//! Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki).
//!
//! Usage is pretty simple:
//!
//! 1. Parse BIP21 as [`payjoin::Uri`](crate::Uri)
//! 2. Construct URI request parameters, a finalized “Original PSBT” paying .amount to .address
//! 3. (optional) Spawn a thread or async task that will broadcast the original PSBT fallback after
//!    delay (e.g. 1 minute) unless canceled
//! 4. Construct the request using [`RequestBuilder`](crate::send::RequestBuilder) with the PSBT
//!    and payjoin uri
//! 5. Send the request and receive response
//! 6. Process the response with
//!    [`Context::process_response()`](crate::send::Context::process_response())
//! 7. Sign and finalize the Payjoin Proposal PSBT
//! 8. Broadcast the Payjoin Transaction (and cancel the optional fallback broadcast)
//!
//! This crate is runtime-agnostic. Data persistence, chain interactions, and networking may be
//! provided by custom implementations or copy the reference
//! [`payjoin-cli`](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-cli) for bitcoind,
//! [`nolooking`](https://github.com/chaincase-app/nolooking) for LND, or
//! [`bitmask-core`](https://github.com/diba-io/bitmask-core) BDK integration. Bring your own
//! wallet and http client.

use std::str::FromStr;

use bitcoin::psbt::Psbt;
use bitcoin::{AddressType, Amount, FeeRate, Script, ScriptBuf, Sequence, TxOut, Weight};
pub use error::{CreateRequestError, ResponseError, ValidationError};
pub(crate) use error::{InternalCreateRequestError, InternalValidationError};
#[cfg(feature = "v2")]
use serde::{Deserialize, Serialize};
use url::Url;

use crate::psbt::{InputPair, PsbtExt};
use crate::request::Request;
#[cfg(feature = "v2")]
use crate::v2::{HpkePublicKey, HpkeSecretKey};
use crate::PjUri;

// See usize casts
#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
compile_error!("This crate currently only supports 32 bit and 64 bit architectures");

mod error;

type InternalResult<T> = Result<T, InternalValidationError>;

#[derive(Clone)]
pub struct RequestBuilder<'a> {
    psbt: Psbt,
    uri: PjUri<'a>,
    disable_output_substitution: bool,
    fee_contribution: Option<(bitcoin::Amount, Option<usize>)>,
    /// Decreases the fee contribution instead of erroring.
    ///
    /// If this option is true and a transaction with change amount lower than fee
    /// contribution is provided then instead of returning error the fee contribution will
    /// be just lowered in the request to match the change amount.
    clamp_fee_contribution: bool,
    min_fee_rate: FeeRate,
}

impl<'a> RequestBuilder<'a> {
    /// Prepare an HTTP request and request context to process the response
    ///
    /// An HTTP client will own the Request data while Context sticks around so
    /// a `(Request, Context)` tuple is returned from `RequestBuilder::build()`
    /// to keep them separated.
    pub fn from_psbt_and_uri(psbt: Psbt, uri: PjUri<'a>) -> Result<Self, CreateRequestError> {
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
    ) -> Result<RequestContext, CreateRequestError> {
        // TODO support optional batched payout scripts. This would require a change to
        // build() which now checks for a single payee.
        let mut payout_scripts = std::iter::once(self.uri.address.script_pubkey());

        // Check if the PSBT is a sweep transaction with only one output that's a payout script and no change
        if self.psbt.unsigned_tx.output.len() == 1
            && payout_scripts.all(|script| script == self.psbt.unsigned_tx.output[0].script_pubkey)
        {
            return self.build_non_incentivizing(min_fee_rate);
        }

        if let Some((additional_fee_index, fee_available)) = self
            .psbt
            .unsigned_tx
            .output
            .clone()
            .into_iter()
            .enumerate()
            .find(|(_, txo)| payout_scripts.all(|script| script != txo.script_pubkey))
            .map(|(i, txo)| (i, txo.value))
        {
            let mut input_pairs = self.psbt.input_pairs().collect::<Vec<InputPair>>().into_iter();
            let first_input_pair =
                input_pairs.next().ok_or(InternalCreateRequestError::NoInputs)?;
            let mut input_weight = first_input_pair
                .expected_input_weight()
                .map_err(InternalCreateRequestError::InputWeight)?;
            for input_pair in input_pairs {
                // use cheapest default if mixed input types
                if input_pair.address_type()? != first_input_pair.address_type()? {
                    input_weight =
                        bitcoin::transaction::InputWeightPrediction::P2TR_KEY_NON_DEFAULT_SIGHASH.weight()
                    // Lengths of txid, index and sequence: (32, 4, 4).
                    + Weight::from_non_witness_data_size(32 + 4 + 4);
                    break;
                }
            }

            let recommended_additional_fee = min_fee_rate * input_weight;
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
        self.build_non_incentivizing(min_fee_rate)
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
    ) -> Result<RequestContext, CreateRequestError> {
        self.fee_contribution = Some((max_fee_contribution, change_index));
        self.clamp_fee_contribution = clamp_fee_contribution;
        self.min_fee_rate = min_fee_rate;
        self.build()
    }

    /// Perform Payjoin without incentivizing the payee to cooperate.
    ///
    /// While it's generally better to offer some contribution some users may wish not to.
    /// This function disables contribution.
    pub fn build_non_incentivizing(
        mut self,
        min_fee_rate: FeeRate,
    ) -> Result<RequestContext, CreateRequestError> {
        // since this is a builder, these should already be cleared
        // but we'll reset them to be sure
        self.fee_contribution = None;
        self.clamp_fee_contribution = false;
        self.min_fee_rate = min_fee_rate;
        self.build()
    }

    fn build(self) -> Result<RequestContext, CreateRequestError> {
        let mut psbt =
            self.psbt.validate().map_err(InternalCreateRequestError::InconsistentOriginalPsbt)?;
        psbt.validate_input_utxos(true)
            .map_err(InternalCreateRequestError::InvalidOriginalInput)?;
        let endpoint = self.uri.extras.endpoint.clone();
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
        let input_type = zeroth_input
            .address_type()
            .map_err(InternalCreateRequestError::AddressType)?
            .to_string();

        Ok(RequestContext {
            psbt,
            endpoint,
            disable_output_substitution,
            fee_contribution,
            payee,
            input_type,
            sequence,
            min_fee_rate: self.min_fee_rate,
            #[cfg(feature = "v2")]
            e: crate::v2::HpkeKeyPair::gen_keypair().secret_key().clone(),
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "v2", derive(Serialize, Deserialize))]
pub struct RequestContext {
    psbt: Psbt,
    endpoint: Url,
    disable_output_substitution: bool,
    fee_contribution: Option<(bitcoin::Amount, usize)>,
    min_fee_rate: FeeRate,
    input_type: String,
    sequence: Sequence,
    payee: ScriptBuf,
    #[cfg(feature = "v2")]
    e: crate::v2::HpkeSecretKey,
}

impl RequestContext {
    /// Extract serialized V1 Request and Context froma Payjoin Proposal
    pub fn extract_v1(&self) -> Result<(Request, ContextV1), CreateRequestError> {
        let url = serialize_url(
            self.endpoint.clone(),
            self.disable_output_substitution,
            self.fee_contribution,
            self.min_fee_rate,
            "1", // payjoin version
        )
        .map_err(InternalCreateRequestError::Url)?;
        let body = self.psbt.to_string().as_bytes().to_vec();
        Ok((
            Request::new_v1(url, body),
            ContextV1 {
                original_psbt: self.psbt.clone(),
                disable_output_substitution: self.disable_output_substitution,
                fee_contribution: self.fee_contribution,
                payee: self.payee.clone(),
                input_type: AddressType::from_str(&self.input_type).expect("Unknown address type"),
                sequence: self.sequence,
                min_fee_rate: self.min_fee_rate,
            },
        ))
    }

    /// Extract serialized Request and Context from a Payjoin Proposal. Automatically selects the correct version.
    ///
    /// In order to support polling, this may need to be called many times to be encrypted with
    /// new unique nonces to make independent OHTTP requests.
    ///
    /// The `ohttp_relay` merely passes the encrypted payload to the ohttp gateway of the receiver
    #[cfg(feature = "v2")]
    pub fn extract_v2(
        &mut self,
        ohttp_relay: Url,
    ) -> Result<(Request, ContextV2), CreateRequestError> {
        use crate::uri::UrlExt;

        if let Some(expiry) = self.endpoint.exp() {
            if std::time::SystemTime::now() > expiry {
                return Err(InternalCreateRequestError::Expired(expiry).into());
            }
        }

        match self.extract_rs_pubkey() {
            Ok(rs) => self.extract_v2_strict(ohttp_relay, rs),
            Err(e) => {
                log::warn!("Failed to extract `rs` pubkey, falling back to v1: {}", e);
                let (req, context_v1) = self.extract_v1()?;
                Ok((req, ContextV2 { context_v1, rs: None, e: None, ohttp_res: None }))
            }
        }
    }

    /// Extract serialized Request and Context from a Payjoin Proposal.
    ///
    /// This method requires the `rs` pubkey to be extracted from the endpoint
    /// and has no fallback to v1.
    #[cfg(feature = "v2")]
    fn extract_v2_strict(
        &mut self,
        ohttp_relay: Url,
        rs: HpkePublicKey,
    ) -> Result<(Request, ContextV2), CreateRequestError> {
        use crate::uri::UrlExt;
        let url = self.endpoint.clone();
        let body = serialize_v2_body(
            &self.psbt,
            self.disable_output_substitution,
            self.fee_contribution,
            self.min_fee_rate,
        )?;
        let body = crate::v2::encrypt_message_a(body, &self.e.clone(), &rs)
            .map_err(InternalCreateRequestError::Hpke)?;
        let mut ohttp =
            self.endpoint.ohttp().ok_or(InternalCreateRequestError::MissingOhttpConfig)?;
        let (body, ohttp_res) =
            crate::v2::ohttp_encapsulate(&mut ohttp, "POST", url.as_str(), Some(&body))
                .map_err(InternalCreateRequestError::OhttpEncapsulation)?;
        log::debug!("ohttp_relay_url: {:?}", ohttp_relay);
        Ok((
            Request::new_v2(ohttp_relay, body),
            ContextV2 {
                context_v1: ContextV1 {
                    original_psbt: self.psbt.clone(),
                    disable_output_substitution: self.disable_output_substitution,
                    fee_contribution: self.fee_contribution,
                    payee: self.payee.clone(),
                    input_type: AddressType::from_str(&self.input_type)
                        .expect("Unknown address type"),
                    sequence: self.sequence,
                    min_fee_rate: self.min_fee_rate,
                },
                rs: Some(self.extract_rs_pubkey()?),
                e: Some(self.e.clone()),
                ohttp_res: Some(ohttp_res),
            },
        ))
    }

    #[cfg(feature = "v2")]
    fn extract_rs_pubkey(&self) -> Result<HpkePublicKey, error::ParseSubdirectoryError> {
        use bitcoin::base64::prelude::BASE64_URL_SAFE_NO_PAD;
        use bitcoin::base64::Engine;
        use error::ParseSubdirectoryError;

        let subdirectory = self
            .endpoint
            .path_segments()
            .and_then(|mut segments| segments.next())
            .ok_or(ParseSubdirectoryError::MissingSubdirectory)?;

        let pubkey_bytes = BASE64_URL_SAFE_NO_PAD
            .decode(subdirectory)
            .map_err(ParseSubdirectoryError::SubdirectoryNotBase64)?;

        HpkePublicKey::from_compressed_bytes(&pubkey_bytes)
            .map_err(ParseSubdirectoryError::SubdirectoryInvalidPubkey)
    }

    pub fn endpoint(&self) -> &Url { &self.endpoint }
}

/// Data required for validation of response.
///
/// This type is used to process the response. Get it from [`RequestBuilder`](crate::send::RequestBuilder)'s build methods.
/// Then you only need to call [`.process_response()`](crate::send::Context::process_response()) on it to continue BIP78 flow.
#[derive(Debug, Clone)]
pub struct ContextV1 {
    original_psbt: Psbt,
    disable_output_substitution: bool,
    fee_contribution: Option<(bitcoin::Amount, usize)>,
    min_fee_rate: FeeRate,
    input_type: AddressType,
    sequence: Sequence,
    payee: ScriptBuf,
}

#[cfg(feature = "v2")]
pub struct ContextV2 {
    context_v1: ContextV1,
    rs: Option<HpkePublicKey>,
    e: Option<HpkeSecretKey>,
    ohttp_res: Option<ohttp::ClientResponse>,
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

#[cfg(feature = "v2")]
impl ContextV2 {
    /// Decodes and validates the response.
    ///
    /// Call this method with response from receiver to continue BIP-??? flow.
    /// A successful response can either be None if the directory has not response yet or Some(Psbt).
    ///
    /// If the response is some valid PSBT you should sign and broadcast.
    #[inline]
    pub fn process_response(
        self,
        response: &mut impl std::io::Read,
    ) -> Result<Option<Psbt>, ResponseError> {
        match (self.ohttp_res, self.rs, self.e) {
            (Some(ohttp_res), Some(rs), Some(e)) => {
                let mut res_buf = Vec::new();
                response.read_to_end(&mut res_buf).map_err(InternalValidationError::Io)?;
                let response = crate::v2::ohttp_decapsulate(ohttp_res, &res_buf)
                    .map_err(InternalValidationError::OhttpEncapsulation)?;
                let body = match response.status() {
                    http::StatusCode::OK => response.body().to_vec(),
                    http::StatusCode::ACCEPTED => return Ok(None),
                    _ => return Err(InternalValidationError::UnexpectedStatusCode)?,
                };
                let psbt = crate::v2::decrypt_message_b(&body, rs, e)
                    .map_err(InternalValidationError::Hpke)?;

                let proposal = Psbt::deserialize(&psbt).map_err(InternalValidationError::Psbt)?;
                let processed_proposal = self.context_v1.process_proposal(proposal)?;
                Ok(Some(processed_proposal))
            }
            _ => self.context_v1.process_response(response).map(Some),
        }
    }
}

impl ContextV1 {
    /// Decodes and validates the response.
    ///
    /// Call this method with response from receiver to continue BIP78 flow. If the response is
    /// valid you will get appropriate PSBT that you should sign and broadcast.
    #[inline]
    pub fn process_response(
        self,
        response: &mut impl std::io::Read,
    ) -> Result<Psbt, ResponseError> {
        let mut res_str = String::new();
        response.read_to_string(&mut res_str).map_err(InternalValidationError::Io)?;
        let proposal = Psbt::from_str(&res_str).map_err(|_| ResponseError::parse(&res_str))?;
        self.process_proposal(proposal).map(Into::into).map_err(Into::into)
    }

    fn process_proposal(self, mut proposal: Psbt) -> InternalResult<Psbt> {
        self.basic_checks(&proposal)?;
        self.check_inputs(&proposal)?;
        let contributed_fee = self.check_outputs(&proposal)?;
        self.restore_original_utxos(&mut proposal)?;
        self.check_fees(&proposal, contributed_fee)?;
        Ok(proposal)
    }

    fn check_fees(&self, proposal: &Psbt, contributed_fee: Amount) -> InternalResult<()> {
        let proposed_fee = proposal.fee().map_err(InternalValidationError::Psbt)?;
        let original_fee = self.original_psbt.fee().map_err(InternalValidationError::Psbt)?;
        ensure!(original_fee <= proposed_fee, AbsoluteFeeDecreased);
        ensure!(contributed_fee <= proposed_fee - original_fee, PayeeTookContributedFee);
        let original_weight = self.original_psbt.clone().extract_tx_unchecked_fee_rate().weight();
        let original_fee_rate = original_fee / original_weight;
        // TODO: This should support mixed input types
        ensure!(
            contributed_fee
                <= original_fee_rate
                    * self
                        .original_psbt
                        .input_pairs()
                        .next()
                        .expect("This shouldn't happen. Failed to get an original input.")
                        .expected_input_weight()
                        .expect("This shouldn't happen. Weight should have been calculated successfully before.")
                    * (proposal.inputs.len() - self.original_psbt.inputs.len()) as u64,
            FeeContributionPaysOutputSizeIncrease
        );
        if self.min_fee_rate > FeeRate::ZERO {
            let proposed_weight = proposal.clone().extract_tx_unchecked_fee_rate().weight();
            ensure!(proposed_fee / proposed_weight >= self.min_fee_rate, FeeRateBelowMinimum);
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
                    // Verify that non_witness_utxo or witness_utxo are filled in.
                    ensure!(
                        proposed.psbtin.witness_utxo.is_some()
                            || proposed.psbtin.non_witness_utxo.is_some(),
                        ReceiverTxinMissingUtxoInfo
                    );
                    ensure!(proposed.txin.sequence == self.sequence, MixedSequence);
                    check_eq!(proposed.address_type()?, self.input_type, MixedInputTypes);
                }
            }
        }
        ensure!(original_inputs.peek().is_none(), MissingOrShuffledInputs);
        Ok(())
    }

    // Restore Original PSBT utxos that the receiver stripped.
    // The BIP78 spec requires utxo information to be removed, but many wallets
    // require it to be present to sign.
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
                    Some((max_fee_contrib, fee_contrib_idx)),
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

fn check_single_payee(
    psbt: &Psbt,
    script_pubkey: &Script,
    amount: Option<bitcoin::Amount>,
) -> Result<(), InternalCreateRequestError> {
    let mut payee_found = false;
    for output in &psbt.unsigned_tx.output {
        if output.script_pubkey == *script_pubkey {
            if let Some(amount) = amount {
                if output.value != amount {
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

fn check_fee_output_amount(
    output: &TxOut,
    fee: bitcoin::Amount,
    clamp_fee_contribution: bool,
) -> Result<bitcoin::Amount, InternalCreateRequestError> {
    if output.value < fee {
        if clamp_fee_contribution {
            Ok(output.value)
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

#[cfg(feature = "v2")]
fn serialize_v2_body(
    psbt: &Psbt,
    disable_output_substitution: bool,
    fee_contribution: Option<(bitcoin::Amount, usize)>,
    min_feerate: FeeRate,
) -> Result<Vec<u8>, CreateRequestError> {
    // Grug say localhost base be discarded anyway. no big brain needed.
    let placeholder_url = serialize_url(
        Url::parse("http://localhost").unwrap(),
        disable_output_substitution,
        fee_contribution,
        min_feerate,
        "2", // payjoin version
    )
    .map_err(InternalCreateRequestError::Url)?;
    let query_params = placeholder_url.query().unwrap_or_default();
    let base64 = psbt.to_string();
    Ok(format!("{}\n{}", base64, query_params).into_bytes())
}

fn serialize_url(
    endpoint: Url,
    disable_output_substitution: bool,
    fee_contribution: Option<(bitcoin::Amount, usize)>,
    min_fee_rate: FeeRate,
    version: &str,
) -> Result<Url, url::ParseError> {
    let mut url = endpoint;
    url.query_pairs_mut().append_pair("v", version);
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

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use bitcoin::psbt::Psbt;
    use bitcoin::FeeRate;

    use crate::psbt::PsbtExt;
    use crate::send::error::{ResponseError, WellKnownError};

    const ORIGINAL_PSBT: &str = "cHNidP8BAHMCAAAAAY8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////AtyVuAUAAAAAF6kUHehJ8GnSdBUOOv6ujXLrWmsJRDCHgIQeAAAAAAAXqRR3QJbbz0hnQ8IvQ0fptGn+votneofTAAAAAAEBIKgb1wUAAAAAF6kU3k4ekGHKWRNbA1rV5tR5kEVDVNCHAQcXFgAUx4pFclNVgo1WWAdN1SYNX8tphTABCGsCRzBEAiB8Q+A6dep+Rz92vhy26lT0AjZn4PRLi8Bf9qoB/CMk0wIgP/Rj2PWZ3gEjUkTlhDRNAQ0gXwTO7t9n+V14pZ6oljUBIQMVmsAaoNWHVMS02LfTSe0e388LNitPa1UQZyOihY+FFgABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUAAA=";
    const PAYJOIN_PROPOSAL: &str = "cHNidP8BAJwCAAAAAo8nutGgJdyYGXWiBEb45Hoe9lWGbkxh/6bNiOJdCDuDAAAAAAD+////jye60aAl3JgZdaIERvjkeh72VYZuTGH/ps2I4l0IO4MBAAAAAP7///8CJpW4BQAAAAAXqRQd6EnwadJ0FQ46/q6NcutaawlEMIcACT0AAAAAABepFHdAltvPSGdDwi9DR+m0af6+i2d6h9MAAAAAAQEgqBvXBQAAAAAXqRTeTh6QYcpZE1sDWtXm1HmQRUNU0IcBBBYAFMeKRXJTVYKNVlgHTdUmDV/LaYUwIgYDFZrAGqDVh1TEtNi300ntHt/PCzYrT2tVEGcjooWPhRYYSFzWUDEAAIABAACAAAAAgAEAAAAAAAAAAAEBIICEHgAAAAAAF6kUyPLL+cphRyyI5GTUazV0hF2R2NWHAQcXFgAUX4BmVeWSTJIEwtUb5TlPS/ntohABCGsCRzBEAiBnu3tA3yWlT0WBClsXXS9j69Bt+waCs9JcjWtNjtv7VgIge2VYAaBeLPDB6HGFlpqOENXMldsJezF9Gs5amvDQRDQBIQJl1jz1tBt8hNx2owTm+4Du4isx0pmdKNMNIjjaMHFfrQABABYAFEb2Giu6c4KO5YW0pfw3lGp9jMUUIgICygvBWB5prpfx61y1HDAwo37kYP3YRJBvAjtunBAur3wYSFzWUDEAAIABAACAAAAAgAEAAAABAAAAAAA=";

    fn create_v1_context() -> super::ContextV1 {
        let original_psbt = Psbt::from_str(ORIGINAL_PSBT).unwrap();
        eprintln!("original: {:#?}", original_psbt);
        let payee = original_psbt.unsigned_tx.output[1].script_pubkey.clone();
        let sequence = original_psbt.unsigned_tx.input[0].sequence;
        let ctx = super::ContextV1 {
            original_psbt,
            disable_output_substitution: false,
            fee_contribution: Some((bitcoin::Amount::from_sat(182), 0)),
            min_fee_rate: FeeRate::ZERO,
            payee,
            input_type: bitcoin::AddressType::P2sh,
            sequence,
        };
        ctx
    }

    #[test]
    fn official_vectors() {
        let original_psbt = Psbt::from_str(ORIGINAL_PSBT).unwrap();
        eprintln!("original: {:#?}", original_psbt);
        let ctx = create_v1_context();
        let mut proposal = Psbt::from_str(PAYJOIN_PROPOSAL).unwrap();
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

    #[test]
    #[should_panic]
    fn test_receiver_steals_sender_change() {
        let original_psbt = Psbt::from_str(ORIGINAL_PSBT).unwrap();
        eprintln!("original: {:#?}", original_psbt);
        let ctx = create_v1_context();
        let mut proposal = Psbt::from_str(PAYJOIN_PROPOSAL).unwrap();
        eprintln!("proposal: {:#?}", proposal);
        for output in proposal.outputs_mut() {
            output.bip32_derivation.clear();
        }
        for input in proposal.inputs_mut() {
            input.bip32_derivation.clear();
        }
        proposal.inputs_mut()[0].witness_utxo = None;
        // Steal 0.5 BTC from the sender output and add it to the receiver output
        proposal.unsigned_tx.output[0].value -= bitcoin::Amount::from_btc(0.5).unwrap();
        proposal.unsigned_tx.output[1].value += bitcoin::Amount::from_btc(0.5).unwrap();
        ctx.process_proposal(proposal).unwrap();
    }

    #[test]
    #[cfg(feature = "v2")]
    fn req_ctx_ser_de_roundtrip() {
        use hpke::Deserializable;

        use super::*;
        let req_ctx = RequestContext {
            psbt: Psbt::from_str(ORIGINAL_PSBT).unwrap(),
            endpoint: Url::parse("http://localhost:1234").unwrap(),
            disable_output_substitution: false,
            fee_contribution: None,
            min_fee_rate: FeeRate::ZERO,
            input_type: bitcoin::AddressType::P2sh.to_string(),
            sequence: Sequence::MAX,
            payee: ScriptBuf::from(vec![0x00]),
            e: HpkeSecretKey(
                <hpke::kem::SecpK256HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(&[0x01; 32])
                    .unwrap(),
            ),
        };
        let serialized = serde_json::to_string(&req_ctx).unwrap();
        let deserialized = serde_json::from_str(&serialized).unwrap();
        assert!(req_ctx == deserialized);
    }

    #[test]
    fn handle_json_errors() {
        let ctx = create_v1_context();
        let known_json_error = serde_json::json!({
            "errorCode": "version-unsupported",
            "message": "This version of payjoin is not supported."
        })
        .to_string();
        match ctx.process_response(&mut known_json_error.as_bytes()) {
            Err(ResponseError::WellKnown(WellKnownError::VersionUnsupported { .. })) =>
                assert!(true),
            _ => panic!("Expected WellKnownError"),
        }

        let ctx = create_v1_context();
        let invalid_json_error = serde_json::json!({
            "err": "random",
            "message": "This version of payjoin is not supported."
        })
        .to_string();
        match ctx.process_response(&mut invalid_json_error.as_bytes()) {
            Err(ResponseError::Validation(_)) => assert!(true),
            _ => panic!("Expected unrecognized JSON error"),
        }
    }
}
