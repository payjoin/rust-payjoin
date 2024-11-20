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
//! 4. Construct the [`Sender`] using [`SenderBuilder`] with the PSBT and payjoin uri
//! 5. Send the request(s) and receive response(s) by following on the extracted [`Context`]
//! 6. Sign and finalize the Payjoin Proposal PSBT
//! 7. Broadcast the Payjoin Transaction (and cancel the optional fallback broadcast)
//!
//! This crate is runtime-agnostic. Data persistence, chain interactions, and networking may be
//! provided by custom implementations or copy the reference
//! [`payjoin-cli`](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-cli) for bitcoind,
//! [`nolooking`](https://github.com/chaincase-app/nolooking) for LND, or
//! [`bitmask-core`](https://github.com/diba-io/bitmask-core) BDK integration. Bring your own
//! wallet and http client.

use std::str::FromStr;

#[cfg(feature = "v2")]
use bitcoin::base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
#[cfg(feature = "v2")]
use bitcoin::hashes::{sha256, Hash};
use bitcoin::psbt::Psbt;
use bitcoin::{Amount, FeeRate, Script, ScriptBuf, TxOut, Weight};
pub use error::{CreateRequestError, ResponseError, ValidationError};
pub(crate) use error::{InternalCreateRequestError, InternalValidationError};
#[cfg(feature = "v2")]
use serde::{Deserialize, Serialize};
use url::Url;

#[cfg(feature = "v2")]
use crate::hpke::{decrypt_message_b, encrypt_message_a, HpkeKeyPair, HpkePublicKey};
#[cfg(feature = "v2")]
use crate::ohttp::{ohttp_decapsulate, ohttp_encapsulate};
use crate::psbt::PsbtExt;
use crate::request::Request;
use crate::PjUri;

// See usize casts
#[cfg(not(any(target_pointer_width = "32", target_pointer_width = "64")))]
compile_error!("This crate currently only supports 32 bit and 64 bit architectures");

mod error;

type InternalResult<T> = Result<T, InternalValidationError>;

#[derive(Clone)]
pub struct SenderBuilder<'a> {
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

impl<'a> SenderBuilder<'a> {
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
    pub fn build_recommended(self, min_fee_rate: FeeRate) -> Result<Sender, CreateRequestError> {
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
            let mut input_pairs = self.psbt.input_pairs();
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
    ) -> Result<Sender, CreateRequestError> {
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
    ) -> Result<Sender, CreateRequestError> {
        // since this is a builder, these should already be cleared
        // but we'll reset them to be sure
        self.fee_contribution = None;
        self.clamp_fee_contribution = false;
        self.min_fee_rate = min_fee_rate;
        self.build()
    }

    fn build(self) -> Result<Sender, CreateRequestError> {
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

        Ok(Sender {
            psbt,
            endpoint,
            disable_output_substitution,
            fee_contribution,
            payee,
            min_fee_rate: self.min_fee_rate,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "v2", derive(Serialize, Deserialize))]
pub struct Sender {
    psbt: Psbt,
    endpoint: Url,
    disable_output_substitution: bool,
    fee_contribution: Option<(bitcoin::Amount, usize)>,
    min_fee_rate: FeeRate,
    payee: ScriptBuf,
}

impl Sender {
    /// Extract serialized V1 Request and Context from a Payjoin Proposal
    pub fn extract_v1(&self) -> Result<(Request, V1Context), CreateRequestError> {
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
            V1Context {
                psbt_context: PsbtContext {
                    original_psbt: self.psbt.clone(),
                    disable_output_substitution: self.disable_output_substitution,
                    fee_contribution: self.fee_contribution,
                    payee: self.payee.clone(),
                    min_fee_rate: self.min_fee_rate,
                    allow_mixed_input_scripts: false,
                },
            },
        ))
    }

    /// Extract serialized Request and Context from a Payjoin Proposal.
    ///
    /// This method requires the `rs` pubkey to be extracted from the endpoint
    /// and has no fallback to v1.
    #[cfg(feature = "v2")]
    pub fn extract_v2(
        &self,
        ohttp_relay: Url, // FIXME: could be &Url and clone inside to help caller
    ) -> Result<(Request, V2PostContext), CreateRequestError> {
        use crate::uri::UrlExt;
        if let Some(expiry) = self.endpoint.exp() {
            if std::time::SystemTime::now() > expiry {
                return Err(InternalCreateRequestError::Expired(expiry).into());
            }
        }
        let rs = self.extract_rs_pubkey()?;
        let url = self.endpoint.clone();
        let body = serialize_v2_body(
            &self.psbt,
            self.disable_output_substitution,
            self.fee_contribution,
            self.min_fee_rate,
        )?;
        let hpke_ctx = HpkeContext::new(rs);
        let body = encrypt_message_a(
            body,
            &hpke_ctx.reply_pair.public_key().clone(),
            &hpke_ctx.receiver.clone(),
        )
        .map_err(InternalCreateRequestError::Hpke)?;
        let mut ohttp =
            self.endpoint.ohttp().ok_or(InternalCreateRequestError::MissingOhttpConfig)?;
        let (body, ohttp_ctx) = ohttp_encapsulate(&mut ohttp, "POST", url.as_str(), Some(&body))
            .map_err(InternalCreateRequestError::OhttpEncapsulation)?;
        log::debug!("ohttp_relay_url: {:?}", ohttp_relay);
        Ok((
            Request::new_v2(ohttp_relay, body),
            V2PostContext {
                endpoint: self.endpoint.clone(),
                psbt_ctx: PsbtContext {
                    original_psbt: self.psbt.clone(),
                    disable_output_substitution: self.disable_output_substitution,
                    fee_contribution: self.fee_contribution,
                    payee: self.payee.clone(),
                    min_fee_rate: self.min_fee_rate,
                    allow_mixed_input_scripts: true,
                },
                hpke_ctx,
                ohttp_ctx,
            },
        ))
    }

    #[cfg(feature = "v2")]
    fn extract_rs_pubkey(
        &self,
    ) -> Result<HpkePublicKey, crate::uri::error::ParseReceiverPubkeyError> {
        use crate::uri::UrlExt;
        self.endpoint.receiver_pubkey()
    }

    pub fn endpoint(&self) -> &Url { &self.endpoint }
}

#[derive(Debug, Clone)]
pub struct V1Context {
    psbt_context: PsbtContext,
}

impl V1Context {
    pub fn process_response(
        self,
        response: &mut impl std::io::Read, // FIXME: could be &[u8] bc you need the whole thing
    ) -> Result<Psbt, ResponseError> {
        self.psbt_context.process_response(response)
    }
}

#[cfg(feature = "v2")]
pub struct V2PostContext {
    endpoint: Url,
    psbt_ctx: PsbtContext,
    hpke_ctx: HpkeContext,
    ohttp_ctx: ohttp::ClientResponse,
}

#[cfg(feature = "v2")]
impl V2PostContext {
    pub fn process_response(
        self,
        response: &[u8], // FIXME: could be &[u8] bc caller doesn't need to track read cursor
    ) -> Result<V2GetContext, ResponseError> {
        let response = ohttp_decapsulate(self.ohttp_ctx, response)
            .map_err(InternalValidationError::OhttpEncapsulation)?;
        match response.status() {
            http::StatusCode::OK => {
                // return OK with new Typestate
                Ok(V2GetContext {
                    endpoint: self.endpoint,
                    psbt_ctx: self.psbt_ctx,
                    hpke_ctx: self.hpke_ctx,
                })
            }
            _ => Err(InternalValidationError::UnexpectedStatusCode)?,
        }
    }
}

#[cfg(feature = "v2")]
#[derive(Debug, Clone)]
pub struct V2GetContext {
    endpoint: Url,
    psbt_ctx: PsbtContext,
    hpke_ctx: HpkeContext,
}

#[cfg(feature = "v2")]
impl V2GetContext {
    pub fn extract_req(
        &self,
        ohttp_relay: Url, // FIXME: could be &Url and clone inside to help caller
    ) -> Result<(Request, ohttp::ClientResponse), CreateRequestError> {
        use crate::uri::UrlExt;
        let mut url = self.endpoint.clone();

        // TODO unify with receiver's fn subdir_path_from_pubkey
        let hash = sha256::Hash::hash(&self.hpke_ctx.reply_pair.public_key().to_compressed_bytes());
        let subdir = BASE64_URL_SAFE_NO_PAD.encode(&hash.as_byte_array()[..8]);
        url.set_path(&subdir);
        let body = encrypt_message_a(
            Vec::new(),
            &self.hpke_ctx.reply_pair.public_key().clone(),
            &self.hpke_ctx.receiver.clone(),
        )
        .map_err(InternalCreateRequestError::Hpke)?;
        let mut ohttp =
            self.endpoint.ohttp().ok_or(InternalCreateRequestError::MissingOhttpConfig)?;
        let (body, ohttp_ctx) = ohttp_encapsulate(&mut ohttp, "GET", url.as_str(), Some(&body))
            .map_err(InternalCreateRequestError::OhttpEncapsulation)?;

        Ok((Request::new_v2(ohttp_relay, body), ohttp_ctx))
    }

    pub fn process_response(
        &self,
        response: &[u8], // FIXME: could be &[u8] bc caller doesn't need to track read cursor
        ohttp_ctx: ohttp::ClientResponse,
    ) -> Result<Option<Psbt>, ResponseError> {
        let response = ohttp_decapsulate(ohttp_ctx, response)
            .map_err(InternalValidationError::OhttpEncapsulation)?;
        let body = match response.status() {
            http::StatusCode::OK => response.body().to_vec(),
            http::StatusCode::ACCEPTED => return Ok(None),
            _ => return Err(InternalValidationError::UnexpectedStatusCode)?,
        };
        let psbt = decrypt_message_b(
            &body,
            self.hpke_ctx.receiver.clone(),
            self.hpke_ctx.reply_pair.secret_key().clone(),
        )
        .map_err(InternalValidationError::Hpke)?;

        let proposal = Psbt::deserialize(&psbt).map_err(InternalValidationError::Psbt)?;
        let processed_proposal = self.psbt_ctx.clone().process_proposal(proposal)?;
        Ok(Some(processed_proposal))
    }
}

/// Data required for validation of response.
///
/// This type is used to process the response. Get it from [`RequestBuilder`]'s build methods.
/// Then you only need to call [`Self::process_response`] on it to continue BIP78 flow.
#[derive(Debug, Clone)]
pub struct PsbtContext {
    original_psbt: Psbt,
    disable_output_substitution: bool,
    fee_contribution: Option<(bitcoin::Amount, usize)>,
    min_fee_rate: FeeRate,
    payee: ScriptBuf,
    allow_mixed_input_scripts: bool,
}

#[cfg(feature = "v2")]
#[derive(Debug, Clone)]
struct HpkeContext {
    receiver: HpkePublicKey,
    reply_pair: HpkeKeyPair,
}

#[cfg(feature = "v2")]
impl HpkeContext {
    fn new(receiver: HpkePublicKey) -> Self {
        Self { receiver, reply_pair: HpkeKeyPair::gen_keypair() }
    }
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

impl PsbtContext {
    /// Decodes and validates the response.
    ///
    /// Call this method with response from receiver to continue BIP78 flow. If the response is
    /// valid you will get appropriate PSBT that you should sign and broadcast.
    #[inline]
    pub fn process_response(
        self,
        response: &mut impl std::io::Read, // FIXME: could be &[u8] or &str ref IF POSSIBLE
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
        let original_spks = self
            .original_psbt
            .input_pairs()
            .map(|input_pair| {
                input_pair
                    .previous_txout()
                    .map_err(InternalValidationError::PrevTxOut)
                    .map(|txout| txout.script_pubkey.clone())
            })
            .collect::<InternalResult<Vec<ScriptBuf>>>()?;
        let additional_input_weight = proposal.input_pairs().try_fold(
            Weight::ZERO,
            |acc, input_pair| -> InternalResult<Weight> {
                let spk = &input_pair
                    .previous_txout()
                    .map_err(InternalValidationError::PrevTxOut)?
                    .script_pubkey;
                if original_spks.contains(spk) {
                    Ok(acc)
                } else {
                    let weight = input_pair
                        .expected_input_weight()
                        .map_err(InternalValidationError::InputWeight)?;
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
                    let original = self
                        .original_psbt
                        .input_pairs()
                        .next()
                        .ok_or(InternalValidationError::NoInputs)?;
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
                    if !self.allow_mixed_input_scripts {
                        check_eq!(
                            proposed.address_type()?,
                            original.address_type()?,
                            MixedInputTypes
                        );
                    }
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
    endpoint: Url, // FIXME: could be &Url and clone inside to help caller
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

    fn create_v1_context() -> super::PsbtContext {
        let original_psbt = Psbt::from_str(ORIGINAL_PSBT).unwrap();
        eprintln!("original: {:#?}", original_psbt);
        let payee = original_psbt.unsigned_tx.output[1].script_pubkey.clone();
        super::PsbtContext {
            original_psbt,
            disable_output_substitution: false,
            fee_contribution: Some((bitcoin::Amount::from_sat(182), 0)),
            min_fee_rate: FeeRate::ZERO,
            payee,
            allow_mixed_input_scripts: false,
        }
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
        use super::*;
        let req_ctx = Sender {
            psbt: Psbt::from_str(ORIGINAL_PSBT).unwrap(),
            endpoint: Url::parse("http://localhost:1234").unwrap(),
            disable_output_substitution: false,
            fee_contribution: None,
            min_fee_rate: FeeRate::ZERO,
            payee: ScriptBuf::from(vec![0x00]),
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
            Err(ResponseError::WellKnown(WellKnownError::VersionUnsupported { .. })) => (),
            _ => panic!("Expected WellKnownError"),
        }

        let ctx = create_v1_context();
        let invalid_json_error = serde_json::json!({
            "err": "random",
            "message": "This version of payjoin is not supported."
        })
        .to_string();
        match ctx.process_response(&mut invalid_json_error.as_bytes()) {
            Err(ResponseError::Validation(_)) => (),
            _ => panic!("Expected unrecognized JSON error"),
        }
    }
}
