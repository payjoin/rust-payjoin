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
pub use error::{CreateRequestError, EncapsulationError};
use error::{InternalCreateRequestError, InternalEncapsulationError};
use ohttp::ClientResponse;
use serde::{Deserialize, Serialize};
pub use session::{replay_event_log, ReplayError, SessionEvent, SessionHistory};
use url::Url;

use super::error::BuildSenderError;
use super::*;
use crate::hpke::{decrypt_message_b, encrypt_message_a, HpkeSecretKey};
use crate::ohttp::{ohttp_encapsulate, process_get_res, process_post_res};
use crate::persist::{
    MaybeBadInitInputsTransition, MaybeFatalTransition, MaybeSuccessTransitionWithNoResults,
};
use crate::send::v1;
use crate::send::v2::session::InternalReplayError;
use crate::uri::{ShortId, UrlExt};
use crate::{HpkeKeyPair, HpkePublicKey, IntoUrl, OhttpKeys, PjUri, Request};

mod error;
mod session;

/// A builder to construct the properties of a [`Sender`].
#[derive(Clone)]
pub struct SenderBuilder<'a>(pub(crate) v1::SenderBuilder<'a>);

impl<'a> SenderBuilder<'a> {
    /// Prepare the context from which to make Sender requests
    ///
    /// Call [`SenderBuilder::build_recommended()`] or other `build` methods
    /// to create a [`Sender`]
    pub fn new(psbt: Psbt, uri: PjUri<'a>) -> Self { Self(v1::SenderBuilder::new(psbt, uri)) }

    /// Disable output substitution even if the receiver didn't.
    ///
    /// This forbids receiver switching output or decreasing amount.
    /// It is generally **not** recommended to set this as it may prevent the receiver from
    /// doing advanced operations such as opening LN channels and it also guarantees the
    /// receiver will **not** reward the sender with a discount.
    pub fn always_disable_output_substitution(self) -> Self {
        Self(self.0.always_disable_output_substitution())
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
    ) -> MaybeBadInitInputsTransition<SessionEvent, Sender<WithReplyKey>, BuildSenderError> {
        self.v2_sender_from_v1(self.0.clone().build_recommended(min_fee_rate))
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
    ) -> MaybeBadInitInputsTransition<SessionEvent, Sender<WithReplyKey>, BuildSenderError> {
        self.v2_sender_from_v1(self.0.clone().build_with_additional_fee(
            max_fee_contribution,
            change_index,
            min_fee_rate,
            clamp_fee_contribution,
        ))
    }

    /// Perform Payjoin without incentivizing the payee to cooperate.
    ///
    /// While it's generally better to offer some contribution some users may wish not to.
    /// This function disables contribution.
    pub fn build_non_incentivizing(
        self,
        min_fee_rate: FeeRate,
    ) -> MaybeBadInitInputsTransition<SessionEvent, Sender<WithReplyKey>, BuildSenderError> {
        self.v2_sender_from_v1(self.0.clone().build_non_incentivizing(min_fee_rate))
    }

    /// Helper function that takes a V1 sender build result and wraps it in a V2 Sender,
    /// returning the appropriate state transition.
    fn v2_sender_from_v1(
        &self,
        v1_result: Result<v1::Sender, BuildSenderError>,
    ) -> MaybeBadInitInputsTransition<SessionEvent, Sender<WithReplyKey>, BuildSenderError> {
        let mut v1 = match v1_result {
            Ok(inner) => inner,
            Err(e) => return MaybeBadInitInputsTransition::bad_init_inputs(e),
        };

        // V2 senders may always ignore the receiver's `pjos` output substitution preference,
        // because all communications with the receiver are end-to-end authenticated.
        if self.0.output_substitution == OutputSubstitution::Enabled {
            v1.psbt_ctx.output_substitution = OutputSubstitution::Enabled;
        }

        let with_reply_key = WithReplyKey { v1, reply_key: HpkeKeyPair::gen_keypair().0 };
        MaybeBadInitInputsTransition::success(
            SessionEvent::CreatedReplyKey(with_reply_key.clone()),
            Sender { state: with_reply_key },
        )
    }
}

pub trait State {}

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
    Uninitialized,
    WithReplyKey(Sender<WithReplyKey>),
    V2GetContext(Sender<V2GetContext>),
    ProposalReceived(Psbt),
    TerminalFailure,
}

impl SendSession {
    fn process_event(self, event: SessionEvent) -> Result<SendSession, ReplayError> {
        match (self, event) {
            (SendSession::Uninitialized, SessionEvent::CreatedReplyKey(sender_with_reply_key)) =>
                Ok(SendSession::WithReplyKey(Sender { state: sender_with_reply_key })),
            (SendSession::WithReplyKey(state), SessionEvent::V2GetContext(v2_get_context)) =>
                Ok(state.apply_v2_get_context(v2_get_context)),
            (SendSession::V2GetContext(_state), SessionEvent::ProposalReceived(proposal)) =>
                Ok(SendSession::ProposalReceived(proposal)),
            (_, SessionEvent::SessionInvalid(_)) => Ok(SendSession::TerminalFailure),
            (current_state, event) => Err(InternalReplayError::InvalidStateAndEvent(
                Box::new(current_state),
                Box::new(event),
            )
            .into()),
        }
    }
}

/// A payjoin V2 sender, allowing the construction of a payjoin V2 request
/// and the resulting [`V2PostContext`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithReplyKey {
    /// The v1 Sender.
    pub(crate) v1: v1::Sender,
    /// The secret key to decrypt the receiver's reply.
    pub(crate) reply_key: HpkeSecretKey,
}

impl State for WithReplyKey {}

impl Sender<WithReplyKey> {
    /// Construct serialized V1 Request and Context from a Payjoin Proposal
    pub fn create_v1_post_request(&self) -> (Request, v1::V1Context) {
        self.v1.create_v1_post_request()
    }

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
        if let Ok(expiry) = self.v1.endpoint.exp() {
            if std::time::SystemTime::now() > expiry {
                return Err(InternalCreateRequestError::Expired(expiry).into());
            }
        }

        let mut ohttp_keys = self
            .v1
            .endpoint()
            .ohttp()
            .map_err(|_| InternalCreateRequestError::MissingOhttpConfig)?;
        let body = serialize_v2_body(
            &self.v1.psbt_ctx.original_psbt,
            self.v1.psbt_ctx.output_substitution,
            self.v1.psbt_ctx.fee_contribution,
            self.v1.psbt_ctx.min_fee_rate,
        )?;
        let (request, ohttp_ctx) = extract_request(
            ohttp_relay,
            self.reply_key.clone(),
            body,
            self.v1.endpoint.clone(),
            self.extract_rs_pubkey()?,
            &mut ohttp_keys,
        )?;
        let rs = self.extract_rs_pubkey()?;
        Ok((
            request,
            V2PostContext {
                endpoint: self.v1.endpoint.clone(),
                psbt_ctx: self.v1.psbt_ctx.clone(),
                hpke_ctx: HpkeContext::new(rs, &self.reply_key),
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
    /// from the receiver using the returned [`V2GetContext`].
    pub fn process_response(
        self,
        response: &[u8],
        post_ctx: V2PostContext,
    ) -> MaybeFatalTransition<SessionEvent, Sender<V2GetContext>, EncapsulationError> {
        match process_post_res(response, post_ctx.ohttp_ctx) {
            Ok(()) => {}
            Err(e) => {
                return MaybeFatalTransition::fatal(
                    SessionEvent::SessionInvalid(e.to_string()),
                    InternalEncapsulationError::DirectoryResponse(e).into(),
                );
            }
        }

        let v2_get_context = V2GetContext {
            endpoint: post_ctx.endpoint,
            psbt_ctx: post_ctx.psbt_ctx,
            hpke_ctx: post_ctx.hpke_ctx,
        };
        MaybeFatalTransition::success(
            SessionEvent::V2GetContext(v2_get_context.clone()),
            Sender { state: v2_get_context },
        )
    }

    pub(crate) fn extract_rs_pubkey(
        &self,
    ) -> Result<HpkePublicKey, crate::uri::url_ext::ParseReceiverPubkeyParamError> {
        self.v1.endpoint.receiver_pubkey()
    }

    /// The endpoint in the Payjoin URI
    pub fn endpoint(&self) -> &Url { self.v1.endpoint() }

    pub(crate) fn apply_v2_get_context(self, v2_get_context: V2GetContext) -> SendSession {
        SendSession::V2GetContext(Sender { state: v2_get_context })
    }
}

pub(crate) fn extract_request(
    ohttp_relay: impl IntoUrl,
    reply_key: HpkeSecretKey,
    body: Vec<u8>,
    url: Url,
    receiver_pubkey: HpkePublicKey,
    ohttp_keys: &mut OhttpKeys,
) -> Result<(Request, ClientResponse), CreateRequestError> {
    let ohttp_relay = ohttp_relay.into_url()?;
    let hpke_ctx = HpkeContext::new(receiver_pubkey, &reply_key);
    let body = encrypt_message_a(
        body,
        &hpke_ctx.reply_pair.public_key().clone(),
        &hpke_ctx.receiver.clone(),
    )
    .map_err(InternalCreateRequestError::Hpke)?;

    let (body, ohttp_ctx) = ohttp_encapsulate(ohttp_keys, "POST", url.as_str(), Some(&body))
        .map_err(InternalCreateRequestError::OhttpEncapsulation)?;
    log::debug!("ohttp_relay_url: {ohttp_relay:?}");
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
    pub(crate) endpoint: Url,
    pub(crate) psbt_ctx: PsbtContext,
    pub(crate) hpke_ctx: HpkeContext,
    pub(crate) ohttp_ctx: ohttp::ClientResponse,
}

/// Data required to validate the GET response.
///
/// This type is used to make a BIP77 GET request and process the response.
/// Call [`Sender<V2GetContext>::process_response`] on it to continue the BIP77 flow.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct V2GetContext {
    /// The endpoint in the Payjoin URI
    pub(crate) endpoint: Url,
    pub(crate) psbt_ctx: PsbtContext,
    pub(crate) hpke_ctx: HpkeContext,
}

impl State for V2GetContext {}

impl Sender<V2GetContext> {
    /// Construct an OHTTP Encapsulated HTTP GET request for the Proposal PSBT
    pub fn create_poll_request(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), CreateRequestError> {
        let base_url = self.endpoint.clone();

        // TODO unify with receiver's fn short_id_from_pubkey
        let hash = sha256::Hash::hash(&self.hpke_ctx.reply_pair.public_key().to_compressed_bytes());
        let mailbox: ShortId = hash.into();
        let url = base_url
            .join(&mailbox.to_string())
            .map_err(|e| InternalCreateRequestError::Url(e.into()))?;
        let body = encrypt_message_a(
            Vec::new(),
            &self.hpke_ctx.reply_pair.public_key().clone(),
            &self.hpke_ctx.receiver.clone(),
        )
        .map_err(InternalCreateRequestError::Hpke)?;
        let mut ohttp =
            self.endpoint.ohttp().map_err(|_| InternalCreateRequestError::MissingOhttpConfig)?;
        let (body, ohttp_ctx) = ohttp_encapsulate(&mut ohttp, "GET", url.as_str(), Some(&body))
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
        &self,
        response: &[u8],
        ohttp_ctx: ohttp::ClientResponse,
    ) -> MaybeSuccessTransitionWithNoResults<SessionEvent, Psbt, Sender<V2GetContext>, ResponseError>
    {
        let body = match process_get_res(response, ohttp_ctx) {
            Ok(Some(body)) => body,
            Ok(None) => return MaybeSuccessTransitionWithNoResults::no_results(self.clone()),
            Err(e) =>
                return MaybeSuccessTransitionWithNoResults::fatal(
                    SessionEvent::SessionInvalid(e.to_string()),
                    InternalEncapsulationError::DirectoryResponse(e).into(),
                ),
        };
        let psbt = match decrypt_message_b(
            &body,
            self.hpke_ctx.receiver.clone(),
            self.hpke_ctx.reply_pair.secret_key().clone(),
        ) {
            Ok(psbt) => psbt,
            Err(e) =>
                return MaybeSuccessTransitionWithNoResults::fatal(
                    SessionEvent::SessionInvalid(e.to_string()),
                    InternalEncapsulationError::Hpke(e).into(),
                ),
        };
        let proposal = match Psbt::deserialize(&psbt) {
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
    pub fn endpoint(&self) -> &Url { &self.endpoint }
}

#[cfg(feature = "v2")]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct HpkeContext {
    pub(crate) receiver: HpkePublicKey,
    pub(crate) reply_pair: HpkeKeyPair,
}

#[cfg(feature = "v2")]
impl HpkeContext {
    pub fn new(receiver: HpkePublicKey, reply_key: &HpkeSecretKey) -> Self {
        Self { receiver, reply_pair: HpkeKeyPair::from_secret_key(reply_key) }
    }
}

#[cfg(test)]
mod test {
    use std::time::{Duration, SystemTime};

    use bitcoin::hex::FromHex;
    use bitcoin::Address;
    use payjoin_test_utils::{BoxError, EXAMPLE_URL, KEM, KEY_ID, PARSED_ORIGINAL_PSBT, SYMMETRIC};

    use super::*;
    use crate::persist::NoopSessionPersister;
    use crate::receive::v2::Receiver;
    use crate::OhttpKeys;

    const SERIALIZED_BODY_V2: &str = "63484e696450384241484d43414141414159386e757447674a647959475857694245623435486f65396c5747626b78682f36624e694f4a6443447544414141414141442b2f2f2f2f41747956754155414141414146366b554865684a38476e536442554f4f7636756a584c72576d734a5244434867495165414141414141415871525233514a62627a30686e513849765130667074476e2b766f746e656f66544141414141414542494b6762317755414141414146366b55336b34656b47484b57524e6241317256357452356b455644564e4348415163584667415578347046636c4e56676f31575741644e3153594e583874706854414243477343527a424541694238512b41366465702b527a393276687932366c5430416a5a6e3450524c6938426639716f422f434d6b30774967502f526a3250575a3367456a556b546c6844524e415130675877544f3774396e2b563134705a366f6c6a554249514d566d7341616f4e5748564d5330324c6654536530653338384c4e697450613155515a794f6968592b464667414241425941464562324769753663344b4f35595730706677336c4770396a4d55554141413d0a763d32";

    fn create_sender_context() -> Result<super::Sender<super::WithReplyKey>, BoxError> {
        let endpoint = Url::parse("http://localhost:1234")?;
        let mut sender = super::Sender {
            state: super::WithReplyKey {
                v1: v1::Sender {
                    endpoint,
                    psbt_ctx: PsbtContext {
                        original_psbt: PARSED_ORIGINAL_PSBT.clone(),
                        output_substitution: OutputSubstitution::Enabled,
                        fee_contribution: None,
                        min_fee_rate: FeeRate::ZERO,
                        payee: ScriptBuf::from(vec![0x00]),
                    },
                },
                reply_key: HpkeKeyPair::gen_keypair().0,
            },
        };
        sender.v1.endpoint.set_exp(SystemTime::now() + Duration::from_secs(60));
        sender.v1.endpoint.set_receiver_pubkey(HpkeKeyPair::gen_keypair().1);
        sender.v1.endpoint.set_ohttp(OhttpKeys(
            ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).expect("valid key config"),
        ));

        Ok(sender)
    }

    #[test]
    fn test_serialize_v2() -> Result<(), BoxError> {
        let sender = create_sender_context()?;
        let body = serialize_v2_body(
            &sender.v1.psbt_ctx.original_psbt,
            sender.v1.psbt_ctx.output_substitution,
            sender.v1.psbt_ctx.fee_contribution,
            sender.v1.psbt_ctx.min_fee_rate,
        );
        assert_eq!(body.as_ref().unwrap(), &<Vec<u8> as FromHex>::from_hex(SERIALIZED_BODY_V2)?,);
        Ok(())
    }

    #[test]
    fn test_extract_v2_success() -> Result<(), BoxError> {
        let sender = create_sender_context()?;
        let ohttp_relay = EXAMPLE_URL.clone();
        let result = sender.create_v2_post_request(ohttp_relay);
        let (request, context) = result.expect("Result should be ok");
        assert!(!request.body.is_empty(), "Request body should not be empty");
        assert_eq!(
            request.url.to_string(),
            format!("{}{}", EXAMPLE_URL.clone(), sender.v1.endpoint.join("/")?)
        );
        assert_eq!(context.endpoint, sender.v1.endpoint);
        assert_eq!(context.psbt_ctx.original_psbt, sender.v1.psbt_ctx.original_psbt);
        Ok(())
    }

    #[test]
    fn test_extract_v2_fails_missing_pubkey() -> Result<(), BoxError> {
        let expected_error = "cannot parse receiver public key: receiver public key is missing";
        let mut sender = create_sender_context()?;
        sender.v1.endpoint.set_fragment(Some(""));
        sender.v1.endpoint.set_exp(SystemTime::now() + Duration::from_secs(60));
        sender.v1.endpoint.set_ohttp(OhttpKeys(
            ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).expect("valid key config"),
        ));
        let ohttp_relay = EXAMPLE_URL.clone();
        let result = sender.create_v2_post_request(ohttp_relay);
        assert!(result.is_err(), "Extract v2 expected receiver pubkey error, but it succeeded");

        match result {
            Ok(_) => panic!("Expected error, got success"),
            Err(error) => assert_eq!(format!("{error}"), expected_error),
        }
        Ok(())
    }

    #[test]
    fn test_extract_v2_fails_missing_ohttp_config() -> Result<(), BoxError> {
        let expected_error = "no ohttp configuration with which to make a v2 request available";
        let mut sender = create_sender_context()?;
        sender.v1.endpoint.set_fragment(Some(""));
        sender.v1.endpoint.set_exp(SystemTime::now() + Duration::from_secs(60));
        sender.v1.endpoint.set_receiver_pubkey(HpkeKeyPair::gen_keypair().1);
        let ohttp_relay = EXAMPLE_URL.clone();
        let result = sender.create_v2_post_request(ohttp_relay);
        assert!(result.is_err(), "Extract v2 expected missing ohttp error, but it succeeded");

        match result {
            Ok(_) => panic!("Expected error, got success"),
            Err(error) => assert_eq!(format!("{error}"), expected_error),
        }
        Ok(())
    }

    #[test]
    fn test_extract_v2_fails_when_expired() -> Result<(), BoxError> {
        let expected_error = "session expired at SystemTime";
        let mut sender = create_sender_context()?;
        let exp_time = std::time::SystemTime::now();
        sender.v1.endpoint.set_exp(exp_time);
        let ohttp_relay = EXAMPLE_URL.clone();
        let result = sender.create_v2_post_request(ohttp_relay);
        assert!(result.is_err(), "Extract v2 expected expiry error, but it succeeded");

        match result {
            Ok(_) => panic!("Expected error, got success"),
            Err(error) => assert_eq!(
                format!("{error}")
                    .split_once(" {")
                    .map_or(format!("{error}"), |(prefix, _)| prefix.to_string()),
                expected_error
            ),
        }
        Ok(())
    }

    #[test]
    fn test_v2_sender_builder() {
        let address = Address::from_str("2N47mmrWXsNBvQR6k78hWJoTji57zXwNcU7")
            .expect("valid address")
            .assume_checked();
        let directory = EXAMPLE_URL.clone();
        let ohttp_keys = OhttpKeys(
            ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).expect("valid key config"),
        );
        let pj_uri = Receiver::create_session(address.clone(), directory, ohttp_keys, None)
            .save(&NoopSessionPersister::default())
            .expect("receiver should succeed")
            .pj_uri();
        let req_ctx = SenderBuilder::new(PARSED_ORIGINAL_PSBT.clone(), pj_uri.clone())
            .build_recommended(FeeRate::BROADCAST_MIN)
            .save(&NoopSessionPersister::default())
            .expect("sender should succeed");
        // v2 senders may always override the receiver's `pjos` parameter to enable output
        // substitution
        assert_eq!(req_ctx.v1.psbt_ctx.output_substitution, OutputSubstitution::Enabled);
        assert_eq!(&req_ctx.v1.psbt_ctx.payee, &address.script_pubkey());
        let fee_contribution =
            req_ctx.v1.psbt_ctx.fee_contribution.expect("sender should contribute fees");
        assert_eq!(fee_contribution.max_amount, Amount::from_sat(91));
        assert_eq!(fee_contribution.vout, 0);
        assert_eq!(req_ctx.v1.psbt_ctx.min_fee_rate, FeeRate::from_sat_per_kwu(250));
        // ensure that the other builder methods also enable output substitution
        let req_ctx = SenderBuilder::new(PARSED_ORIGINAL_PSBT.clone(), pj_uri.clone())
            .build_non_incentivizing(FeeRate::BROADCAST_MIN)
            .save(&NoopSessionPersister::default())
            .expect("sender should succeed");
        assert_eq!(req_ctx.v1.psbt_ctx.output_substitution, OutputSubstitution::Enabled);
        let req_ctx = SenderBuilder::new(PARSED_ORIGINAL_PSBT.clone(), pj_uri.clone())
            .build_with_additional_fee(Amount::ZERO, Some(0), FeeRate::BROADCAST_MIN, false)
            .save(&NoopSessionPersister::default())
            .expect("sender should succeed");
        assert_eq!(req_ctx.v1.psbt_ctx.output_substitution, OutputSubstitution::Enabled);
        // ensure that a v2 sender may still disable output substitution if they prefer.
        let req_ctx = SenderBuilder::new(PARSED_ORIGINAL_PSBT.clone(), pj_uri)
            .always_disable_output_substitution()
            .build_recommended(FeeRate::BROADCAST_MIN)
            .save(&NoopSessionPersister::default())
            .expect("sender should succeed");
        assert_eq!(req_ctx.v1.psbt_ctx.output_substitution, OutputSubstitution::Disabled);
    }
}
