//! Send BIP 77 Payjoin v2
//!
//! This module contains types and methods used to implement sending via [BIP77
//! Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md).
//!
//! Usage is pretty simple:
//!
//! 1. Parse BIP21 as [`payjoin::Uri`](crate::Uri)
//! 2. Construct URI request parameters, a finalized “Original PSBT” paying .amount to .address
//! 3. (optional) Spawn a thread or async task that will broadcast the original PSBT fallback after
//!    delay (e.g. 1 minute) unless canceled
//! 4. Construct the [`Sender`] using [`SenderBuilder`] with the PSBT and payjoin uri
//! 5. Send the request(s) and receive response(s) by following on the extracted Context
//! 6. Sign and finalize the Payjoin Proposal PSBT
//! 7. Broadcast the Payjoin Transaction (and cancel the optional fallback broadcast)
//!
//! This crate is runtime-agnostic. Data persistence, chain interactions, and networking may be
//! provided by custom implementations or copy the reference
//! [`payjoin-cli`](https://github.com/payjoin/rust-payjoin/tree/master/payjoin-cli) for bitcoind,
//! [`nolooking`](https://github.com/chaincase-app/nolooking) for LND, or
//! [`bitmask-core`](https://github.com/diba-io/bitmask-core) BDK integration. Bring your own
//! wallet and http client.
//!
//! OHTTP Privacy Warning
//! Encapsulated requests whether GET or POST—**must not be retried or reused**.
//! Retransmitting the same ciphertext (including via automatic retries) breaks the unlinkability and privacy guarantees of OHTTP,
//! as it allows the relay to correlate requests by comparing ciphertexts.
//! Note: Even fresh requests may be linkable via metadata (e.g. client IP, request timing),
//! but request reuse makes correlation trivial for the relay.

use bitcoin::hashes::{sha256, Hash};
use bitcoin::Address;
pub use error::{CreateRequestError, EncapsulationError};
use error::{InternalCreateRequestError, InternalEncapsulationError};
use ohttp::ClientResponse;
use serde::{Deserialize, Serialize};
pub use session::{replay_event_log, SessionEvent, SessionHistory};
use url::Url;

use super::error::BuildSenderError;
use super::*;
use crate::error::{InternalReplayError, ReplayError};
use crate::hpke::{decrypt_message_b, encrypt_message_a, HpkeSecretKey};
use crate::ohttp::{ohttp_encapsulate, process_get_res, process_post_res};
use crate::persist::{
    MaybeFatalTransition, MaybeSuccessTransitionWithNoResults, NextStateTransition,
};
use crate::uri::v2::PjParam;
use crate::uri::ShortId;
use crate::{HpkeKeyPair, HpkePublicKey, IntoUrl, OhttpKeys, PjUri, Request};

mod error;
mod session;

/// A builder to construct the properties of a [`Sender`].
/// V2 SenderBuilder differs from V1 in that it does not allow the receiver's output substitution preference to be disabled.
/// This is because all communications with the receiver are end-to-end authenticated. So a
/// malicious man in the middle can't substitute outputs, only the receiver can.
/// The receiver can always choose not to substitute outputs, however.
#[derive(Clone)]
pub struct SenderBuilder {
    pj_param: crate::uri::v2::PjParam,
    output_substitution: OutputSubstitution,
    psbt_ctx_builder: PsbtContextBuilder,
}

impl SenderBuilder {
    /// Prepare the context from which to make Sender requests
    ///
    /// Call [`SenderBuilder::build_recommended()`] or other `build` methods
    /// to create a [`Sender`]
    pub fn new(psbt: Psbt, uri: PjUri) -> Self {
        match uri.extras.pj_param {
            #[cfg(feature = "v1")]
            crate::uri::PjParam::V1(_) => unimplemented!("V2 SenderBuilder only supports v2 URLs"),
            crate::uri::PjParam::V2(pj_param) =>
                Self::from_parts(psbt, &pj_param, &uri.address, uri.amount),
        }
    }

    pub fn from_parts(
        psbt: Psbt,
        pj_param: &PjParam,
        address: &Address,
        amount: Option<Amount>,
    ) -> Self {
        Self {
            pj_param: pj_param.clone(),
            // Ignore the receiver's output substitution preference, because all
            // communications with the receiver are end-to-end authenticated. So a
            // malicious man in the middle can't substitute outputs, only the receiver can.
            output_substitution: OutputSubstitution::Enabled,
            psbt_ctx_builder: PsbtContextBuilder::new(psbt, address.script_pubkey(), amount),
        }
    }

    /// Disable output substitution even if the receiver didn't.
    ///
    /// This forbids receiver switching output or decreasing amount.
    /// It is generally **not** recommended to set this as it may prevent the receiver from
    /// doing advanced operations such as opening LN channels and it also guarantees the
    /// receiver will **not** reward the sender with a discount.
    pub fn always_disable_output_substitution(self) -> Self {
        Self { output_substitution: OutputSubstitution::Disabled, ..self }
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
    ) -> Result<NextStateTransition<SessionEvent, Sender<WithReplyKey>>, BuildSenderError> {
        let psbt_ctx =
            self.psbt_ctx_builder.build_recommended(min_fee_rate, self.output_substitution)?;
        Ok(Self::v2_transition_from_psbt_ctx(self.pj_param, psbt_ctx))
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
        self,
        max_fee_contribution: bitcoin::Amount,
        change_index: Option<usize>,
        min_fee_rate: FeeRate,
        clamp_fee_contribution: bool,
    ) -> Result<NextStateTransition<SessionEvent, Sender<WithReplyKey>>, BuildSenderError> {
        let psbt_ctx = self.psbt_ctx_builder.build_with_additional_fee(
            max_fee_contribution,
            change_index,
            min_fee_rate,
            clamp_fee_contribution,
            self.output_substitution,
        )?;
        Ok(Self::v2_transition_from_psbt_ctx(self.pj_param, psbt_ctx))
    }

    /// Perform Payjoin without incentivizing the payee to cooperate.
    ///
    /// While it's generally better to offer some contribution some users may wish not to.
    /// This function disables contribution.
    pub fn build_non_incentivizing(
        self,
        min_fee_rate: FeeRate,
    ) -> Result<NextStateTransition<SessionEvent, Sender<WithReplyKey>>, BuildSenderError> {
        let psbt_ctx = self
            .psbt_ctx_builder
            .build_non_incentivizing(min_fee_rate, self.output_substitution)?;
        Ok(Self::v2_transition_from_psbt_ctx(self.pj_param, psbt_ctx))
    }

    /// Helper function that takes a V1 sender build result and wraps it in a V2 Sender,
    /// returning the appropriate state transition.
    fn v2_transition_from_psbt_ctx(
        pj_param: PjParam,
        psbt_ctx: PsbtContext,
    ) -> NextStateTransition<SessionEvent, Sender<WithReplyKey>> {
        let with_reply_key = WithReplyKey::new(pj_param, psbt_ctx);
        NextStateTransition::success(
            SessionEvent::CreatedReplyKey(with_reply_key.clone()),
            Sender { state: with_reply_key },
        )
    }
}

mod sealed {
    pub trait State {}

    impl State for super::WithReplyKey {}
    impl State for super::PollingForProposal {}
}

/// Sealed trait for V2 send session states.
///
/// This trait is sealed to prevent external implementations. Only types within this crate
/// can implement this trait, ensuring type safety and protocol integrity.
pub trait State: sealed::State {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sender<State> {
    pub(crate) state: State,
}

impl<State> core::ops::Deref for Sender<State> {
    type Target = State;

    fn deref(&self) -> &Self::Target { &self.state }
}

impl<State> core::ops::DerefMut for Sender<State> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.state }
}

/// Represents the various states of a Payjoin send session during the protocol flow.
///
/// This provides type erasure for the send session state, allowing the session to be replayed
/// and the state to be updated with the next event over a uniform interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendSession {
    WithReplyKey(Sender<WithReplyKey>),
    PollingForProposal(Sender<PollingForProposal>),
    ProposalReceived(Psbt),
    TerminalFailure,
}

impl SendSession {
    fn new(context: WithReplyKey) -> Self { SendSession::WithReplyKey(Sender { state: context }) }

    fn process_event(
        self,
        event: SessionEvent,
    ) -> Result<SendSession, ReplayError<Self, SessionEvent>> {
        match (self, event) {
            (
                SendSession::WithReplyKey(state),
                SessionEvent::PollingForProposal(polling_for_proposal),
            ) => Ok(state.apply_polling_for_proposal(polling_for_proposal)),
            (SendSession::PollingForProposal(_state), SessionEvent::ProposalReceived(proposal)) =>
                Ok(SendSession::ProposalReceived(proposal)),
            (_, SessionEvent::SessionInvalid(_)) => Ok(SendSession::TerminalFailure),
            (current_state, event) => Err(InternalReplayError::InvalidEvent(
                Box::new(event),
                Some(Box::new(current_state)),
            )
            .into()),
        }
    }
}

/// A payjoin V2 sender, allowing the construction of a payjoin V2 request
/// and the resulting [`V2PostContext`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithReplyKey {
    /// The endpoint in the Payjoin URI
    pub(crate) pj_param: PjParam,
    /// The Original PSBT context
    pub(crate) psbt_ctx: PsbtContext,
    /// The secret key to decrypt the receiver's reply.
    pub(crate) reply_key: HpkeSecretKey,
}

impl WithReplyKey {
    fn new(pj_param: PjParam, psbt_ctx: PsbtContext) -> Self {
        Self { pj_param, psbt_ctx, reply_key: HpkeKeyPair::gen_keypair().0 }
    }
}

impl Sender<WithReplyKey> {
    /// Construct serialized Request and Context from a Payjoin Proposal.
    ///
    /// Important: This request must not be retried or reused on failure.
    /// Retransmitting the same ciphertext breaks OHTTP privacy properties.
    /// The specific concern is that the relay can see that a request is being retried,
    /// which leaks that it's all the same request.
    ///
    /// This method requires the `rs` pubkey to be extracted from the endpoint
    /// and has no fallback to v1.
    pub fn create_v2_post_request(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, V2PostContext), CreateRequestError> {
        if self.pj_param.expiration().elapsed() {
            return Err(InternalCreateRequestError::Expired(self.pj_param.expiration()).into());
        }

        let mut sanitized_psbt = self.psbt_ctx.original_psbt.clone();
        clear_unneeded_fields(&mut sanitized_psbt);
        let body = serialize_v2_body(
            &sanitized_psbt,
            self.psbt_ctx.output_substitution,
            self.psbt_ctx.fee_contribution,
            self.psbt_ctx.min_fee_rate,
        )?;
        let base_url = self.pj_param.endpoint().clone();
        let ohttp_keys = self.pj_param.ohttp_keys();
        let (request, ohttp_ctx) = extract_request(
            ohttp_relay,
            self.reply_key.clone(),
            body,
            base_url,
            self.pj_param.receiver_pubkey().clone(),
            ohttp_keys,
        )?;
        Ok((
            request,
            V2PostContext {
                pj_param: self.pj_param.clone(),
                psbt_ctx: self.psbt_ctx.clone(),
                reply_key: self.reply_key.clone(),
                ohttp_ctx,
            },
        ))
    }

    /// Processes the response for the initial POST message from the sender
    /// client in the v2 Payjoin protocol.
    ///
    /// This function decapsulates the response using the provided OHTTP
    /// context. If the encapsulated response status is successful, it
    /// indicates that the the Original PSBT been accepted. Otherwise, it
    /// returns an error with the encapsulated response status code.
    ///
    /// After this function is called, the sender can poll for a Proposal PSBT
    /// from the receiver using the returned [`PollingForProposal`].
    pub fn process_response(
        self,
        response: &[u8],
        post_ctx: V2PostContext,
    ) -> MaybeFatalTransition<SessionEvent, Sender<PollingForProposal>, EncapsulationError> {
        match process_post_res(response, post_ctx.ohttp_ctx) {
            Ok(()) => {}
            Err(e) =>
                if e.is_fatal() {
                    return MaybeFatalTransition::fatal(
                        SessionEvent::SessionInvalid(e.to_string()),
                        InternalEncapsulationError::DirectoryResponse(e).into(),
                    );
                } else {
                    return MaybeFatalTransition::transient(
                        InternalEncapsulationError::DirectoryResponse(e).into(),
                    );
                },
        }

        let polling_for_proposal = PollingForProposal {
            pj_param: post_ctx.pj_param,
            psbt_ctx: post_ctx.psbt_ctx,
            reply_key: post_ctx.reply_key,
        };
        MaybeFatalTransition::success(
            SessionEvent::PollingForProposal(polling_for_proposal.clone()),
            Sender { state: polling_for_proposal },
        )
    }

    /// The endpoint in the Payjoin URI
    pub fn endpoint(&self) -> Url { self.pj_param.endpoint().clone() }

    pub(crate) fn apply_polling_for_proposal(
        self,
        polling_for_proposal: PollingForProposal,
    ) -> SendSession {
        SendSession::PollingForProposal(Sender { state: polling_for_proposal })
    }
}

pub(crate) fn extract_request(
    ohttp_relay: impl IntoUrl,
    reply_key: HpkeSecretKey,
    body: Vec<u8>,
    url: Url,
    receiver_pubkey: HpkePublicKey,
    ohttp_keys: &OhttpKeys,
) -> Result<(Request, ClientResponse), CreateRequestError> {
    let ohttp_relay = ohttp_relay.into_url()?;
    let body = encrypt_message_a(
        body,
        &HpkeKeyPair::from_secret_key(&reply_key).public_key().clone(),
        &receiver_pubkey,
    )
    .map_err(InternalCreateRequestError::Hpke)?;

    let (body, ohttp_ctx) = ohttp_encapsulate(ohttp_keys, "POST", url.as_str(), Some(&body))
        .map_err(InternalCreateRequestError::OhttpEncapsulation)?;
    tracing::debug!("ohttp_relay_url: {ohttp_relay:?}");
    let directory_base = url.join("/").map_err(|e| InternalCreateRequestError::Url(e.into()))?;
    let full_ohttp_relay = ohttp_relay
        .join(&format!("/{directory_base}"))
        .map_err(|e| InternalCreateRequestError::Url(e.into()))?;
    let request = Request::new_v2(&full_ohttp_relay, &body);
    Ok((request, ohttp_ctx))
}

pub(crate) fn serialize_v2_body(
    psbt: &Psbt,
    output_substitution: OutputSubstitution,
    fee_contribution: Option<AdditionalFeeContribution>,
    min_fee_rate: FeeRate,
) -> Result<Vec<u8>, CreateRequestError> {
    // Grug say localhost base be discarded anyway. no big brain needed.
    let base_url = Url::parse("http://localhost").expect("invalid URL");

    let placeholder_url =
        serialize_url(base_url, output_substitution, fee_contribution, min_fee_rate, Version::Two);
    let query_params = placeholder_url.query().unwrap_or_default();
    let base64 = psbt.to_string();
    Ok(format!("{base64}\n{query_params}").into_bytes())
}

/// Data required to validate the POST response.
///
/// This type is used to process a BIP77 POST response.
/// Call [`Sender<V2PostContext>::process_response`] on it to continue the BIP77 flow.
pub struct V2PostContext {
    /// The endpoint in the Payjoin URI
    pub(crate) pj_param: PjParam,
    pub(crate) psbt_ctx: PsbtContext,
    pub(crate) reply_key: HpkeSecretKey,
    pub(crate) ohttp_ctx: ohttp::ClientResponse,
}

/// Data required to validate the GET response.
///
/// This type is used to make a BIP77 GET request and process the response.
/// Call [`Sender<PollingForProposal>::process_response`] on it to continue the BIP77 flow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PollingForProposal {
    /// The endpoint in the Payjoin URI
    pub(crate) pj_param: PjParam,
    pub(crate) psbt_ctx: PsbtContext,
    pub(crate) reply_key: HpkeSecretKey,
}

impl ResponseError {
    fn from_slice(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        let trimmed_bytes = bytes.split(|&byte| byte == 0).next().unwrap_or(bytes);
        let value: serde_json::Value = serde_json::from_slice(trimmed_bytes)?;
        Ok(ResponseError::from_json(value))
    }
}

impl Sender<PollingForProposal> {
    /// Construct an OHTTP Encapsulated HTTP GET request for the Proposal PSBT
    pub fn create_poll_request(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), CreateRequestError> {
        // TODO unify with receiver's fn short_id_from_pubkey
        let hash = sha256::Hash::hash(
            &HpkeKeyPair::from_secret_key(&self.reply_key).public_key().to_compressed_bytes(),
        );
        let mailbox: ShortId = hash.into();
        let url = self
            .endpoint()
            .join(&mailbox.to_string())
            .map_err(|e| InternalCreateRequestError::Url(e.into()))?;
        let body = encrypt_message_a(
            Vec::new(),
            HpkeKeyPair::from_secret_key(&self.reply_key).public_key(),
            self.pj_param.receiver_pubkey(),
        )
        .map_err(InternalCreateRequestError::Hpke)?;
        let ohttp_keys = self.pj_param.ohttp_keys();
        let (body, ohttp_ctx) = ohttp_encapsulate(ohttp_keys, "GET", url.as_str(), Some(&body))
            .map_err(InternalCreateRequestError::OhttpEncapsulation)?;

        let url = ohttp_relay.into_url().map_err(InternalCreateRequestError::Url)?;
        Ok((Request::new_v2(&url, &body), ohttp_ctx))
    }

    /// Processes the response for the final GET message from the sender client
    /// in the v2 Payjoin protocol.
    ///
    /// This function decapsulates the response using the provided OHTTP
    /// context. A successful response can either be a Proposal PSBT or an
    /// ACCEPTED message indicating no Proposal PSBT is available yet.
    /// Otherwise, it returns an error with the encapsulated status code.
    ///
    /// After this function is called, the sender can sign and finalize the
    /// PSBT and broadcast the resulting Payjoin transaction to the network.
    pub fn process_response(
        self,
        response: &[u8],
        ohttp_ctx: ohttp::ClientResponse,
    ) -> MaybeSuccessTransitionWithNoResults<
        SessionEvent,
        Psbt,
        Sender<PollingForProposal>,
        ResponseError,
    > {
        let body = match process_get_res(response, ohttp_ctx) {
            Ok(Some(body)) => body,
            Ok(None) => return MaybeSuccessTransitionWithNoResults::no_results(self.clone()),
            Err(e) =>
                if e.is_fatal() {
                    return MaybeSuccessTransitionWithNoResults::fatal(
                        SessionEvent::SessionInvalid(e.to_string()),
                        InternalEncapsulationError::DirectoryResponse(e).into(),
                    );
                } else {
                    return MaybeSuccessTransitionWithNoResults::transient(
                        InternalEncapsulationError::DirectoryResponse(e).into(),
                    );
                },
        };

        let body = match decrypt_message_b(
            &body,
            self.pj_param.receiver_pubkey().clone(),
            self.reply_key.clone(),
        ) {
            Ok(body) => body,
            Err(e) =>
                return MaybeSuccessTransitionWithNoResults::fatal(
                    SessionEvent::SessionInvalid(e.to_string()),
                    InternalEncapsulationError::Hpke(e).into(),
                ),
        };

        if let Ok(resp_err) = ResponseError::from_slice(&body) {
            return MaybeSuccessTransitionWithNoResults::fatal(
                SessionEvent::SessionInvalid(resp_err.to_string()),
                resp_err,
            );
        }

        let proposal = match Psbt::deserialize(&body) {
            Ok(proposal) => proposal,
            Err(e) =>
                return MaybeSuccessTransitionWithNoResults::fatal(
                    SessionEvent::SessionInvalid(e.to_string()),
                    InternalProposalError::Psbt(e).into(),
                ),
        };
        let processed_proposal = match self.psbt_ctx.clone().process_proposal(proposal) {
            Ok(processed_proposal) => processed_proposal,
            Err(e) =>
                return MaybeSuccessTransitionWithNoResults::fatal(
                    SessionEvent::SessionInvalid(e.to_string()),
                    e.into(),
                ),
        };

        MaybeSuccessTransitionWithNoResults::success(
            processed_proposal.clone(),
            SessionEvent::ProposalReceived(processed_proposal),
        )
    }

    pub fn endpoint(&self) -> Url { self.pj_param.endpoint() }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use std::time::{Duration, SystemTime};

    use bitcoin::hex::FromHex;
    use bitcoin::Address;
    use payjoin_test_utils::{BoxError, EXAMPLE_URL, KEM, KEY_ID, PARSED_ORIGINAL_PSBT, SYMMETRIC};

    use super::*;
    use crate::persist::NoopSessionPersister;
    use crate::receive::v2::ReceiverBuilder;
    use crate::time::Time;
    use crate::OhttpKeys;

    const SERIALIZED_BODY_V2: &str = "63484e696450384241484d43414141414159386e757447674a647959475857694245623435486f65396c5747626b78682f36624e694f4a6443447544414141414141442b2f2f2f2f41747956754155414141414146366b554865684a38476e536442554f4f7636756a584c72576d734a5244434867495165414141414141415871525233514a62627a30686e513849765130667074476e2b766f746e656f66544141414141414542494b6762317755414141414146366b55336b34656b47484b57524e6241317256357452356b455644564e4348415163584667415578347046636c4e56676f31575741644e3153594e583874706854414243477343527a424541694238512b41366465702b527a393276687932366c5430416a5a6e3450524c6938426639716f422f434d6b30774967502f526a3250575a3367456a556b546c6844524e415130675877544f3774396e2b563134705a366f6c6a554249514d566d7341616f4e5748564d5330324c6654536530653338384c4e697450613155515a794f6968592b464667414241425941464562324769753663344b4f35595730706677336c4770396a4d55554141413d0a763d32";

    fn create_sender_context(
        expiration: Time,
    ) -> Result<super::Sender<super::WithReplyKey>, BoxError> {
        let endpoint = Url::parse("http://localhost:1234")?;
        let pj_param = crate::uri::v2::PjParam::new(
            endpoint,
            crate::uri::ShortId::try_from(&b"12345670"[..]).expect("valid short id"),
            expiration,
            OhttpKeys(
                ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).expect("valid key config"),
            ),
            HpkeKeyPair::gen_keypair().1,
        );
        Ok(super::Sender {
            state: super::WithReplyKey {
                pj_param,
                psbt_ctx: PsbtContext {
                    original_psbt: PARSED_ORIGINAL_PSBT.clone(),
                    output_substitution: OutputSubstitution::Enabled,
                    fee_contribution: None,
                    min_fee_rate: FeeRate::ZERO,
                    payee: ScriptBuf::from(vec![0x00]),
                },
                reply_key: HpkeKeyPair::gen_keypair().0,
            },
        })
    }

    #[test]
    fn test_serialize_v2() -> Result<(), BoxError> {
        let expiration =
            Time::from_now(Duration::from_secs(60)).expect("expiration should be valid");
        let sender = create_sender_context(expiration)?;
        let body = serialize_v2_body(
            &sender.psbt_ctx.original_psbt,
            sender.psbt_ctx.output_substitution,
            sender.psbt_ctx.fee_contribution,
            sender.psbt_ctx.min_fee_rate,
        );
        assert_eq!(body.as_ref().unwrap(), &<Vec<u8> as FromHex>::from_hex(SERIALIZED_BODY_V2)?,);
        Ok(())
    }

    #[test]
    fn test_extract_v2_success() -> Result<(), BoxError> {
        let expiration =
            Time::from_now(Duration::from_secs(60)).expect("expiration should be valid");
        let sender = create_sender_context(expiration)?;
        let ohttp_relay = EXAMPLE_URL;
        let result = sender.create_v2_post_request(ohttp_relay);
        let (request, context) = result.expect("Result should be ok");
        assert!(!request.body.is_empty(), "Request body should not be empty");
        assert_eq!(
            request.url.to_string(),
            format!("{}/{}", EXAMPLE_URL, sender.pj_param.endpoint().join("/")?)
        );
        assert_eq!(context.psbt_ctx.original_psbt, sender.psbt_ctx.original_psbt);
        Ok(())
    }

    #[test]
    fn test_extract_v2_fails_when_expired() -> Result<(), BoxError> {
        // Create a sender with an already expired timestamp
        let expiration = Time::try_from(SystemTime::now() - Duration::from_secs(1))
            .expect("time in the past should be representable");

        let sender = create_sender_context(expiration)?;
        let ohttp_relay = EXAMPLE_URL;
        let result = sender.create_v2_post_request(ohttp_relay);
        assert!(result.is_err(), "Extract v2 expected expiration error, but it succeeded");

        match result {
            Ok(_) => panic!("Expected error, got success"),
            Err(error) => assert_eq!(format!("{error}"), "session expired",),
        }
        Ok(())
    }

    #[test]
    fn test_v2_sender_builder() {
        let address = Address::from_str("2N47mmrWXsNBvQR6k78hWJoTji57zXwNcU7")
            .expect("valid address")
            .assume_checked();
        let directory = EXAMPLE_URL;
        let ohttp_keys = OhttpKeys(
            ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).expect("valid key config"),
        );
        let pj_uri = ReceiverBuilder::new(address.clone(), directory, ohttp_keys)
            .expect("constructor on test vector should not fail")
            .build()
            .save(&NoopSessionPersister::default())
            .expect("receiver should succeed")
            .pj_uri();
        let req_ctx = SenderBuilder::new(PARSED_ORIGINAL_PSBT.clone(), pj_uri.clone())
            .build_recommended(FeeRate::BROADCAST_MIN)
            .expect("build on test vector should succeed")
            .save(&NoopSessionPersister::default())
            .expect("sender should succeed");
        // v2 senders may always override the receiver's `pjos` parameter to enable output
        // substitution
        assert_eq!(req_ctx.state.psbt_ctx.output_substitution, OutputSubstitution::Enabled);
        assert_eq!(&req_ctx.state.psbt_ctx.payee, &address.script_pubkey());
        let fee_contribution =
            req_ctx.state.psbt_ctx.fee_contribution.expect("sender should contribute fees");
        assert_eq!(fee_contribution.max_amount, Amount::from_sat(91));
        assert_eq!(fee_contribution.vout, 0);
        assert_eq!(req_ctx.state.psbt_ctx.min_fee_rate, FeeRate::from_sat_per_kwu(250));
        // ensure that the other builder methods also enable output substitution
        let req_ctx = SenderBuilder::new(PARSED_ORIGINAL_PSBT.clone(), pj_uri.clone())
            .build_non_incentivizing(FeeRate::BROADCAST_MIN)
            .expect("build on test vector should succeed")
            .save(&NoopSessionPersister::default())
            .expect("sender should succeed");
        assert_eq!(req_ctx.state.psbt_ctx.output_substitution, OutputSubstitution::Enabled);
        let req_ctx = SenderBuilder::new(PARSED_ORIGINAL_PSBT.clone(), pj_uri.clone())
            .build_with_additional_fee(Amount::ZERO, Some(0), FeeRate::BROADCAST_MIN, false)
            .expect("build on test vector should succeed")
            .save(&NoopSessionPersister::default())
            .expect("sender should succeed");
        assert_eq!(req_ctx.state.psbt_ctx.output_substitution, OutputSubstitution::Enabled);
        // ensure that a v2 sender may still disable output substitution if they prefer.
        let req_ctx = SenderBuilder::new(PARSED_ORIGINAL_PSBT.clone(), pj_uri)
            .always_disable_output_substitution()
            .build_recommended(FeeRate::BROADCAST_MIN)
            .expect("build on test vector should succeed")
            .save(&NoopSessionPersister::default())
            .expect("sender should succeed");
        assert_eq!(req_ctx.state.psbt_ctx.output_substitution, OutputSubstitution::Disabled);
    }
}
