//! Receive BIP 77 Payjoin v2
//!
//! This module contains the typestates and helper methods to perform a Payjoin v2 receive.
//!
//! Receiving Payjoin transactions securely and privately requires the receiver to run safety
//! checks on the sender's original proposal, followed by actually making the input and output
//! contributions and modifications before sending the Payjoin proposal back to the sender. All
//! safety check and contribution/modification logic is identical between Payjoin v1 and v2.
//!
//! Additionally, this module also provides tools to manage
//! multiple Payjoin sessions which the receiver may have in progress at any given time.
//! The receiver can pause and resume Payjoin sessions when networking is available by using a
//! Payjoin directory as a store-and-forward server, and keep track of the success and failure of past sessions.
//!
//! See the typestate and function documentation on how to proceed through the receiver protocol
//! flow.
//!
//! For more information on Payjoin v2, see [BIP 77: Async Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md).
//!
//! ## OHTTP Privacy Warning
//! Encapsulated requests whether GET or POST—**must not be retried or reused**.
//! Retransmitting the same ciphertext (including via automatic retries) breaks the unlinkability and privacy guarantees of OHTTP,
//! as it allows the relay to correlate requests by comparing ciphertexts.
//! Note: Even fresh requests may be linkable via metadata (e.g. client IP, request timing),
//! but request reuse makes correlation trivial for the relay.

use std::str::FromStr;
use std::time::{Duration, SystemTime};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::psbt::Psbt;
use bitcoin::{Address, Amount, FeeRate, OutPoint, Script, TxOut};
pub(crate) use error::InternalSessionError;
pub use error::SessionError;
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use session::InternalReplayError;
pub use session::{replay_event_log, ReplayError, SessionEvent, SessionHistory};
use url::Url;

use super::error::{Error, InputContributionError};
use super::{
    common, InternalPayloadError, JsonReply, OutputSubstitutionError, ProtocolError, SelectionError,
};
use crate::hpke::{decrypt_message_a, encrypt_message_b, HpkeKeyPair, HpkePublicKey};
use crate::ohttp::{
    ohttp_encapsulate, process_get_res, process_post_res, OhttpEncapsulationError, OhttpKeys,
};
use crate::output_substitution::OutputSubstitution;
use crate::persist::{
    MaybeFatalTransition, MaybeFatalTransitionWithNoResults, MaybeSuccessTransition,
    MaybeTransientTransition, NextStateTransition,
};
use crate::receive::{parse_payload, InputPair, OriginalPayload, PsbtContext};
use crate::uri::ShortId;
use crate::{ImplementationError, IntoUrl, IntoUrlError, Request, Version};

mod error;
mod session;

const SUPPORTED_VERSIONS: &[Version] = &[Version::One, Version::Two];

static TWENTY_FOUR_HOURS_DEFAULT_EXPIRY: Duration = Duration::from_secs(60 * 60 * 24);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionContext {
    #[serde(deserialize_with = "deserialize_address_assume_checked")]
    address: Address,
    directory: url::Url,
    mailbox: Option<url::Url>,
    ohttp_keys: OhttpKeys,
    expiry: SystemTime,
    amount: Option<Amount>,
    receiver_key: HpkeKeyPair,
    reply_key: Option<HpkePublicKey>,
    max_fee_rate: FeeRate,
}

impl SessionContext {
    fn full_relay_url(&self, ohttp_relay: impl IntoUrl) -> Result<Url, InternalSessionError> {
        let relay_base = ohttp_relay.into_url().map_err(InternalSessionError::ParseUrl)?;

        // Only reveal scheme and authority to the relay
        let directory_base =
            self.directory.join("/").map_err(|e| InternalSessionError::ParseUrl(e.into()))?;

        // Append that information as a path to the relay URL
        relay_base
            .join(&format!("/{directory_base}"))
            .map_err(|e| InternalSessionError::ParseUrl(e.into()))
    }

    /// The mailbox ID where the receiver expects the sender's Original PSBT.
    pub(crate) fn proposal_mailbox_id(&self) -> ShortId {
        short_id_from_pubkey(self.receiver_key.public_key())
    }

    /// The mailbox ID where replies (the Proposal PSBT or errors) should
    /// be sent. For V1 requests this is the same as the proposal mailbox ID.
    // FIXME before the UncheckedOriginalPayload typestate is reached, this returns the
    // proposal mailbox ID. It doesn't make sense to reply before receiving
    // anything from the sender and at that point it's ambiguous whether it's a
    // v2 or v1 sender anyway. Ideally this should be impossible leveraging the
    // typestate machinery
    pub(crate) fn reply_mailbox_id(&self) -> ShortId {
        short_id_from_pubkey(self.reply_key.as_ref().unwrap_or(self.receiver_key.public_key()))
    }
}

fn deserialize_address_assume_checked<'de, D>(deserializer: D) -> Result<Address, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let address = Address::from_str(&s).map_err(serde::de::Error::custom)?;
    Ok(address.assume_checked())
}

fn short_id_from_pubkey(pubkey: &HpkePublicKey) -> ShortId {
    sha256::Hash::hash(&pubkey.to_compressed_bytes()).into()
}

/// Represents the various states of a Payjoin receiver session during the protocol flow.
/// Each variant parameterizes a `Receiver` with a specific state type, and [`ReceiveSession::TerminalFailure`] which indicates the session has ended or is invalid.
///
/// This provides type erasure for the receive session state, allowing for the session to be replayed
/// and the state to be updated with the next event over a uniform interface.
#[derive(Debug, Clone, PartialEq)]
pub enum ReceiveSession {
    Initialized(Receiver<Initialized>),
    UncheckedOriginalPayload(Receiver<UncheckedOriginalPayload>),
    MaybeInputsOwned(Receiver<MaybeInputsOwned>),
    MaybeInputsSeen(Receiver<MaybeInputsSeen>),
    OutputsUnknown(Receiver<OutputsUnknown>),
    WantsOutputs(Receiver<WantsOutputs>),
    WantsInputs(Receiver<WantsInputs>),
    WantsFeeRange(Receiver<WantsFeeRange>),
    ProvisionalProposal(Receiver<ProvisionalProposal>),
    PayjoinProposal(Receiver<PayjoinProposal>),
    TerminalFailure,
}

impl ReceiveSession {
    fn new(event: SessionEvent) -> Result<Self, ReplayError> {
        match event {
            SessionEvent::Created(context) =>
                Ok(ReceiveSession::Initialized(Receiver { state: Initialized { context } })),
            _ =>
                Err(InternalReplayError::InvalidEventForUninitializedSession(Box::new(event))
                    .into()),
        }
    }

    fn process_event(self, event: SessionEvent) -> Result<ReceiveSession, ReplayError> {
        match (self, event) {
            (ReceiveSession::Uninitialized, SessionEvent::Created(context)) =>
                Ok(ReceiveSession::Initialized(Receiver { state: Initialized { context } })),

            (
                ReceiveSession::Initialized(state),
                SessionEvent::UncheckedOriginalPayload((proposal, reply_key)),
            ) => Ok(state.apply_unchecked_from_payload(proposal, reply_key)?),

            (ReceiveSession::UncheckedOriginalPayload(state), SessionEvent::MaybeInputsOwned()) =>
                Ok(state.apply_maybe_inputs_owned()),

            (ReceiveSession::MaybeInputsOwned(state), SessionEvent::MaybeInputsSeen()) =>
                Ok(state.apply_maybe_inputs_seen()),

            (ReceiveSession::MaybeInputsSeen(state), SessionEvent::OutputsUnknown()) =>
                Ok(state.apply_outputs_unknown()),

            (ReceiveSession::OutputsUnknown(state), SessionEvent::WantsOutputs(wants_outputs)) =>
                Ok(state.apply_wants_outputs(wants_outputs)),

            (ReceiveSession::WantsOutputs(state), SessionEvent::WantsInputs(wants_inputs)) =>
                Ok(state.apply_wants_inputs(wants_inputs)),

            (ReceiveSession::WantsInputs(state), SessionEvent::WantsFeeRange(wants_fee_range)) =>
                Ok(state.apply_wants_fee_range(wants_fee_range)),

            (
                ReceiveSession::WantsFeeRange(state),
                SessionEvent::ProvisionalProposal(psbt_context),
            ) => Ok(state.apply_provisional_proposal(psbt_context)),

            (
                ReceiveSession::ProvisionalProposal(state),
                SessionEvent::PayjoinProposal(payjoin_proposal),
            ) => Ok(state.apply_payjoin_proposal(payjoin_proposal)),

            (_, SessionEvent::SessionInvalid(_, _)) => Ok(ReceiveSession::TerminalFailure),
            (current_state, event) => Err(InternalReplayError::InvalidStateAndEvent(
                Box::new(current_state),
                Box::new(event),
            )
            .into()),
        }
    }
}

mod sealed {
    pub trait State {}

    impl State for super::Initialized {}
    impl State for super::UncheckedOriginalPayload {}
    impl State for super::MaybeInputsOwned {}
    impl State for super::MaybeInputsSeen {}
    impl State for super::OutputsUnknown {}
    impl State for super::WantsOutputs {}
    impl State for super::WantsInputs {}
    impl State for super::WantsFeeRange {}
    impl State for super::ProvisionalProposal {}
    impl State for super::PayjoinProposal {}
}

/// Sealed trait for V2 receive session states.
///
/// Any typestate should implement this trait to be considered a part of the protocol flow.
/// This trait is sealed to prevent external implementations. Only types within this crate
/// can implement this trait, ensuring type safety and protocol integrity.
pub trait State: sealed::State {}

/// A higher-level receiver construct which will be taken through different states through the
/// protocol workflow.
///
/// A Payjoin receiver is responsible for receiving the original proposal from the sender, making
/// various safety checks, contributing and/or changing inputs and outputs, and sending the Payjoin
/// proposal back to the sender before they sign off on the receiver's contributions and broadcast
/// the transaction.
///
/// From a code/implementation perspective, Payjoin Development Kit uses a typestate pattern to
/// help receivers go through the entire Payjoin protocol flow. Each typestate has
/// various functions to accomplish the goals of the typestate, and one or more functions which
/// will commit the changes/checks in the current typestate and move to the next one. For more
/// information on the typestate pattern, see [The Typestate Pattern in Rust](https://cliffle.com/blog/rust-typestate/).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receiver<State> {
    /// Data associated with the current state of the receiver.
    pub(crate) state: State,
}

impl<State> core::ops::Deref for Receiver<State> {
    type Target = State;

    fn deref(&self) -> &Self::Target { &self.state }
}

impl<State> core::ops::DerefMut for Receiver<State> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.state }
}

/// Construct an OHTTP Encapsulated HTTP POST request to return
/// a Receiver Error Response
fn extract_err_req(
    err: &JsonReply,
    ohttp_relay: impl IntoUrl,
    session_context: &SessionContext,
) -> Result<(Request, ohttp::ClientResponse), SessionError> {
    if SystemTime::now() > session_context.expiry {
        return Err(InternalSessionError::Expired(session_context.expiry).into());
    }
    let mailbox = mailbox_endpoint(&session_context.directory, &session_context.reply_mailbox_id());
    let (body, ohttp_ctx) = ohttp_encapsulate(
        &mut session_context.ohttp_keys.0.clone(),
        "POST",
        mailbox.as_str(),
        Some(err.to_json().to_string().as_bytes()),
    )
    .map_err(InternalSessionError::OhttpEncapsulation)?;
    let req = Request::new_v2(&session_context.full_relay_url(ohttp_relay)?, &body);
    Ok((req, ohttp_ctx))
}

/// Process an OHTTP Encapsulated HTTP POST Error response
/// to ensure it has been posted properly
pub fn process_err_res(body: &[u8], context: ohttp::ClientResponse) -> Result<(), SessionError> {
    process_post_res(body, context).map_err(|e| InternalSessionError::DirectoryResponse(e).into())
}

#[derive(Debug, Clone)]
pub struct ReceiverBuilder(SessionContext);

impl ReceiverBuilder {
    /// Creates a new [`ReceiverBuilder`] with the provided parameters.
    ///
    /// This is the beginning of the receiver protocol in Payjoin v2. It uses the passed address,
    /// store-and-forward Payjoin directory URL, and the OHTTP keys to encrypt and decrypt HTTP
    /// requests and responses to initialize a Payjoin v2 session.
    ///
    /// Expiration time can be optionally defined to set when the session expires (due to
    /// inactivity of either party, etc.) or otherwise set to a default of 24 hours.
    ///
    /// See [BIP 77: Payjoin Version 2: Serverless Payjoin](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
    /// for more information on the purpose of each parameter for secure Payjoin v2 functionality.
    pub fn new(
        address: Address,
        directory: impl IntoUrl,
        ohttp_keys: OhttpKeys,
    ) -> Result<Self, IntoUrlError> {
        let directory = directory.into_url()?;
        let session_context = SessionContext {
            address,
            directory,
            ohttp_keys,
            receiver_key: HpkeKeyPair::gen_keypair(),
            expiry: SystemTime::now() + TWENTY_FOUR_HOURS_DEFAULT_EXPIRY,
            amount: None,
            mailbox: None,
            reply_key: None,
            max_fee_rate: FeeRate::BROADCAST_MIN,
        };
        Ok(Self(session_context))
    }

    pub fn with_expiry(self, expiry: Duration) -> Self {
        Self(SessionContext { expiry: SystemTime::now() + expiry, ..self.0 })
    }

    pub fn with_amount(self, amount: Amount) -> Self {
        Self(SessionContext { amount: Some(amount), ..self.0 })
    }

    pub fn with_mailbox(self, mailbox: impl IntoUrl) -> Result<Self, IntoUrlError> {
        Ok(Self(SessionContext { mailbox: Some(mailbox.into_url()?), ..self.0 }))
    }

    /// Set the maximum effective fee rate the receiver is willing to pay for their own input/output contributions
    pub fn with_max_fee_rate(self, max_fee_rate: FeeRate) -> Self {
        Self(SessionContext { max_fee_rate, ..self.0 })
    }

    pub fn build(self) -> NextStateTransition<SessionEvent, Receiver<Initialized>> {
        NextStateTransition::success(
            SessionEvent::Created(self.0.clone()),
            Receiver { state: Initialized { context: self.0 } },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Initialized {
    context: SessionContext,
}

impl Receiver<Initialized> {
    /// construct an OHTTP Encapsulated HTTP GET request for the Original PSBT
    pub fn create_poll_request(
        &mut self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), Error> {
        if SystemTime::now() > self.context.expiry {
            return Err(InternalSessionError::Expired(self.context.expiry).into());
        }
        let (body, ohttp_ctx) =
            self.fallback_req_body().map_err(InternalSessionError::OhttpEncapsulation)?;
        let req = Request::new_v2(&self.context.full_relay_url(ohttp_relay)?, &body);
        Ok((req, ohttp_ctx))
    }

    /// The response can either be an UncheckedOriginalPayload or an ACCEPTED message
    /// indicating no UncheckedOriginalPayload is available yet.
    pub fn process_response(
        &mut self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> MaybeFatalTransitionWithNoResults<
        SessionEvent,
        Receiver<UncheckedOriginalPayload>,
        Receiver<Initialized>,
        Error,
    > {
        let current_state = self.clone();
        let proposal = match self.inner_process_res(body, context) {
            Ok(proposal) => proposal,
            Err(e) =>
                return MaybeFatalTransitionWithNoResults::fatal(
                    SessionEvent::SessionInvalid(e.to_string(), None),
                    e,
                ),
        };

        if let Some((proposal, reply_key)) = proposal {
            MaybeFatalTransitionWithNoResults::success(
                SessionEvent::UncheckedOriginalPayload((proposal.clone(), reply_key.clone())),
                Receiver {
                    state: UncheckedOriginalPayload {
                        original: proposal,
                        session_context: SessionContext { reply_key, ..self.state.context.clone() },
                    },
                },
            )
        } else {
            MaybeFatalTransitionWithNoResults::no_results(current_state)
        }
    }

    fn inner_process_res(
        &mut self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> Result<Option<(OriginalPayload, Option<HpkePublicKey>)>, Error> {
        let body = match process_get_res(body, context)
            .map_err(InternalSessionError::DirectoryResponse)?
        {
            Some(body) => body,
            None => return Ok(None),
        };
        match std::str::from_utf8(&body) {
            // V1 response bodies are utf8 plaintext
            Ok(response) =>
                Ok(Some(self.extract_proposal_from_v1(response).map(|original| (original, None))?)),
            // V2 response bodies are encrypted binary
            Err(_) => Ok(Some(
                self.extract_proposal_from_v2(body)
                    .map(|(original, reply_key)| (original, Some(reply_key)))?,
            )),
        }
    }

    fn fallback_req_body(
        &mut self,
    ) -> Result<
        ([u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES], ohttp::ClientResponse),
        OhttpEncapsulationError,
    > {
        let fallback_target =
            mailbox_endpoint(&self.context.directory, &self.context.proposal_mailbox_id());
        ohttp_encapsulate(&mut self.context.ohttp_keys, "GET", fallback_target.as_str(), None)
    }

    fn extract_proposal_from_v1(
        &mut self,
        response: &str,
    ) -> Result<OriginalPayload, ProtocolError> {
        self.unchecked_from_payload(response)
    }

    fn extract_proposal_from_v2(
        &mut self,
        response: Vec<u8>,
    ) -> Result<(OriginalPayload, HpkePublicKey), Error> {
        let (payload_bytes, reply_key) =
            decrypt_message_a(&response, self.context.receiver_key.secret_key().clone())?;
        let payload = std::str::from_utf8(&payload_bytes)
            .map_err(|e| ProtocolError::OriginalPayload(InternalPayloadError::Utf8(e).into()))?;
        self.unchecked_from_payload(payload).map_err(Error::Protocol).map(|p| (p, reply_key))
    }

    fn unchecked_from_payload(&mut self, payload: &str) -> Result<OriginalPayload, ProtocolError> {
        let (base64, padded_query) = payload.split_once('\n').unwrap_or_default();
        let query = padded_query.trim_matches('\0');
        tracing::trace!("Received query: {query}, base64: {base64}"); // my guess is no \n so default is wrong
        let (psbt, mut params) = parse_payload(base64, query, SUPPORTED_VERSIONS)
            .map_err(ProtocolError::OriginalPayload)?;

        // Output substitution must be disabled for V1 sessions in V2 contexts.
        //
        // V2 contexts depend on a payjoin directory to store and forward payjoin
        // proposals. Plaintext V1 proposals are vulnerable to output replacement
        // attacks by a malicious directory if output substitution is not disabled.
        // V2 proposals are authenticated and encrypted to prevent such attacks.
        //
        // see: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#unsecured-payjoin-server
        if params.v == Version::One {
            params.output_substitution = OutputSubstitution::Disabled;
        }

        let inner = OriginalPayload { psbt, params };
        Ok(inner)
    }

    /// Build a V2 Payjoin URI from the receiver's context
    pub fn pj_uri<'a>(&self) -> crate::PjUri<'a> {
        pj_uri(&self.context, OutputSubstitution::Disabled)
    }

    pub(crate) fn apply_unchecked_from_payload(
        self,
        event: OriginalPayload,
        reply_key: Option<HpkePublicKey>,
    ) -> Result<ReceiveSession, InternalReplayError> {
        if self.state.context.expiry < SystemTime::now() {
            // Session is expired, close the session
            return Err(InternalReplayError::SessionExpired(self.state.context.expiry));
        }

        let new_state = Receiver {
            state: UncheckedOriginalPayload {
                original: event,
                session_context: SessionContext { reply_key, ..self.state.context },
            },
        };

        Ok(ReceiveSession::UncheckedOriginalPayload(new_state))
    }
}

/// The sender's original PSBT and optional parameters
///
/// This type is used to process the request. It is returned by
/// [`Receiver::process_response()`].
///
#[derive(Debug, Clone, PartialEq)]
pub struct UncheckedOriginalPayload {
    pub(crate) original: OriginalPayload,
    pub(crate) session_context: SessionContext,
}

/// The original PSBT and the optional parameters received from the sender.
///
/// This is the first typestate after the retrieval of the sender's original proposal in
/// the receiver's workflow. At this stage, the receiver can verify that the original PSBT they have
/// received from the sender is broadcastable to the network in the case of a payjoin failure.
///
/// The recommended usage of this typestate differs based on whether you are implementing an
/// interactive (where the receiver takes manual actions to respond to the
/// payjoin proposal) or a non-interactive (ex. a donation page which automatically generates a new QR code
/// for each visit) payment receiver. For the latter, you should call [`Receiver<UncheckedOriginalPayload>::check_broadcast_suitability`] to check
/// that the proposal is actually broadcastable (and, optionally, whether the fee rate is above the
/// minimum limit you have set). These mechanisms protect the receiver against probing attacks, where
/// a malicious sender can repeatedly send proposals to have the non-interactive receiver reveal the UTXOs
/// it owns with the proposals it modifies.
///
/// If you are implementing an interactive payment receiver, then such checks are not necessary, and you
/// can go ahead with calling [`Receiver<UncheckedOriginalPayload>::assume_interactive_receiver`] to move on to the next typestate.
impl Receiver<UncheckedOriginalPayload> {
    /// Checks that the original PSBT in the proposal can be broadcasted.
    ///
    /// If the receiver is a non-interactive payment processor (ex. a donation page which generates
    /// a new QR code for each visit), then it should make sure that the original PSBT is broadcastable
    /// as a fallback mechanism in case the payjoin fails. This validation would be equivalent to
    /// `testmempoolaccept` RPC call returning `{"allowed": true,...}`.
    ///
    /// Receiver can optionally set a minimum fee rate which will be enforced on the original PSBT in the proposal.
    /// This can be used to further prevent probing attacks since the attacker would now need to probe the receiver
    /// with transactions which are both broadcastable and pay high fee. Unrelated to the probing attack scenario,
    /// this parameter also makes operating in a high fee environment easier for the receiver.
    pub fn check_broadcast_suitability(
        self,
        min_fee_rate: Option<FeeRate>,
        can_broadcast: impl Fn(&bitcoin::Transaction) -> Result<bool, ImplementationError>,
    ) -> MaybeFatalTransition<SessionEvent, Receiver<MaybeInputsOwned>, Error> {
        match self.state.original.check_broadcast_suitability(min_fee_rate, can_broadcast) {
            Ok(()) => MaybeFatalTransition::success(
                SessionEvent::MaybeInputsOwned(),
                Receiver {
                    state: MaybeInputsOwned {
                        original: self.original.clone(),
                        session_context: self.session_context.clone(),
                    },
                },
            ),
            Err(Error::Implementation(e)) =>
                MaybeFatalTransition::transient(Error::Implementation(e)),
            Err(e) => MaybeFatalTransition::fatal(
                SessionEvent::SessionInvalid(e.to_string(), Some(JsonReply::from(&e))),
                e,
            ),
        }
    }

    /// Moves on to the next typestate without any of the current typestate's validations.
    ///
    /// Use this for interactive payment receivers, where there is no risk of a probing attack since the
    /// receiver needs to manually create payjoin URIs.
    pub fn assume_interactive_receiver(
        self,
    ) -> NextStateTransition<SessionEvent, Receiver<MaybeInputsOwned>> {
        NextStateTransition::success(
            SessionEvent::MaybeInputsOwned(),
            Receiver {
                state: MaybeInputsOwned {
                    original: self.original.clone(),
                    session_context: self.state.session_context,
                },
            },
        )
    }

    pub(crate) fn apply_maybe_inputs_owned(self) -> ReceiveSession {
        let new_state = Receiver {
            state: MaybeInputsOwned {
                original: self.original.clone(),
                session_context: self.state.session_context,
            },
        };
        ReceiveSession::MaybeInputsOwned(new_state)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MaybeInputsOwned {
    original: OriginalPayload,
    session_context: SessionContext,
}

/// Typestate to check that the original PSBT has no inputs owned by the receiver.
///
/// At this point, it has been verified that the transaction is broadcastable from previous
/// typestate. The receiver can call [`Receiver<MaybeInputsOwned>::extract_tx_to_schedule_broadcast`]
/// to extract the signed original PSBT to schedule a fallback in case the Payjoin process fails.
///
/// Call [`Receiver<MaybeInputsOwned>::check_inputs_not_owned`] to proceed.
impl Receiver<MaybeInputsOwned> {
    /// Extracts the original transaction received from the sender.
    ///
    /// Use this for scheduling the broadcast of the original transaction as a fallback
    /// for the payjoin. Note that this function does not make any validation on whether
    /// the transaction is broadcastable; it simply extracts it.
    pub fn extract_tx_to_schedule_broadcast(&self) -> bitcoin::Transaction {
        self.original.psbt.clone().extract_tx_unchecked_fee_rate()
    }

    /// Check that the original PSBT has no receiver-owned inputs.
    ///
    /// An attacker can try to spend the receiver's own inputs. This check prevents that.
    pub fn check_inputs_not_owned(
        self,
        is_owned: &mut impl FnMut(&Script) -> Result<bool, ImplementationError>,
    ) -> MaybeFatalTransition<SessionEvent, Receiver<MaybeInputsSeen>, Error> {
        match self.state.original.check_inputs_not_owned(is_owned) {
            Ok(inner) => inner,
            Err(e) => match e {
                Error::Implementation(_) => {
                    return MaybeFatalTransition::transient(e);
                }
                _ => {
                    return MaybeFatalTransition::fatal(
                        SessionEvent::SessionInvalid(e.to_string(), Some(JsonReply::from(&e))),
                        e,
                    );
                }
            },
        };
        MaybeFatalTransition::success(
            SessionEvent::MaybeInputsSeen(),
            Receiver {
                state: MaybeInputsSeen {
                    original: self.original.clone(),
                    session_context: self.state.session_context,
                },
            },
        )
    }

    pub(crate) fn apply_maybe_inputs_seen(self) -> ReceiveSession {
        let new_state = Receiver {
            state: MaybeInputsSeen {
                original: self.original.clone(),
                session_context: self.state.session_context,
            },
        };
        ReceiveSession::MaybeInputsSeen(new_state)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MaybeInputsSeen {
    original: OriginalPayload,
    session_context: SessionContext,
}

/// Typestate to check that the original PSBT has no inputs that the receiver has seen before.
///
/// Call [`Receiver<MaybeInputsSeen>::check_no_inputs_seen_before`] to proceed.
impl Receiver<MaybeInputsSeen> {
    /// Check that the receiver has never seen the inputs in the original proposal before.
    ///
    /// This check prevents the following attacks:
    /// 1. Probing attacks, where the sender can use the exact same proposal (or with minimal change)
    ///    to have the receiver reveal their UTXO set by contributing to all proposals with different inputs
    ///    and sending them back to the receiver.
    /// 2. Re-entrant payjoin, where the sender uses the payjoin PSBT of a previous payjoin as the
    ///    original proposal PSBT of the current, new payjoin.
    pub fn check_no_inputs_seen_before(
        self,
        is_known: &mut impl FnMut(&OutPoint) -> Result<bool, ImplementationError>,
    ) -> MaybeFatalTransition<SessionEvent, Receiver<OutputsUnknown>, Error> {
        match self.state.original.check_no_inputs_seen_before(is_known) {
            Ok(inner) => inner,
            Err(e) => match e {
                Error::Implementation(_) => {
                    return MaybeFatalTransition::transient(e);
                }
                _ => {
                    return MaybeFatalTransition::fatal(
                        SessionEvent::SessionInvalid(e.to_string(), Some(JsonReply::from(&e))),
                        e,
                    );
                }
            },
        };
        MaybeFatalTransition::success(
            SessionEvent::OutputsUnknown(),
            Receiver {
                state: OutputsUnknown {
                    original: self.original.clone(),
                    session_context: self.state.session_context,
                },
            },
        )
    }

    pub(crate) fn apply_outputs_unknown(self) -> ReceiveSession {
        let new_state = Receiver {
            state: OutputsUnknown {
                original: self.original.clone(),
                session_context: self.state.session_context,
            },
        };
        ReceiveSession::OutputsUnknown(new_state)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OutputsUnknown {
    original: OriginalPayload,
    session_context: SessionContext,
}

/// Typestate to check that the outputs of the original PSBT actually pay to the receiver.
///
/// The receiver should only accept the original PSBTs from the sender which actually send them
/// money.
///
/// Call [`Receiver<OutputsUnknown>::identify_receiver_outputs`] to proceed.
impl Receiver<OutputsUnknown> {
    /// Validates whether the original PSBT contains outputs which pay to the receiver and only
    /// then proceeds to the next typestate.
    ///
    /// Additionally, this function also protects the receiver from accidentally subtracting fees
    /// from their own outputs: when a sender is sending a proposal,
    /// they can select an output which they want the receiver to subtract fees from to account for
    /// the increased transaction size. If a sender specifies a receiver output for this purpose, this
    /// function sets that parameter to None so that it is ignored in subsequent steps of the
    /// receiver flow. This protects the receiver from accidentally subtracting fees from their own
    /// outputs.
    pub fn identify_receiver_outputs(
        self,
        is_receiver_output: &mut impl FnMut(&Script) -> Result<bool, ImplementationError>,
    ) -> MaybeFatalTransition<SessionEvent, Receiver<WantsOutputs>, Error> {
        let owned_vouts = match self.state.original.identify_receiver_outputs(is_receiver_output) {
            Ok(inner) => inner,
            Err(e) => match e {
                Error::Implementation(_) => {
                    return MaybeFatalTransition::transient(e);
                }
                _ => {
                    return MaybeFatalTransition::fatal(
                        SessionEvent::SessionInvalid(e.to_string(), Some(JsonReply::from(&e))),
                        e,
                    );
                }
            },
        };
        let inner = common::WantsOutputs::new(self.state.original, owned_vouts);
        MaybeFatalTransition::success(
            SessionEvent::WantsOutputs(inner.clone()),
            Receiver { state: WantsOutputs { inner, session_context: self.state.session_context } },
        )
    }

    pub(crate) fn apply_wants_outputs(self, inner: common::WantsOutputs) -> ReceiveSession {
        let new_state =
            Receiver { state: WantsOutputs { inner, session_context: self.state.session_context } };
        ReceiveSession::WantsOutputs(new_state)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WantsOutputs {
    inner: common::WantsOutputs,
    session_context: SessionContext,
}

/// Typestate which the receiver may substitute or add outputs to.
///
/// In addition to contributing new inputs to an existing PSBT, Payjoin allows the
/// receiver to substitute the original PSBT's outputs to potentially preserve privacy and batch transfers.
/// The receiver does not have to limit themselves to the address shared with the sender in the
/// original Payjoin URI, and can make substitutions of the existing outputs in the proposal.
///
/// Call [`Receiver<WantsOutputs>::commit_outputs`] to proceed.
impl Receiver<WantsOutputs> {
    /// Whether the receiver is allowed to substitute original outputs or not.
    pub fn output_substitution(&self) -> OutputSubstitution { self.inner.output_substitution() }

    /// Substitute the receiver output script with the provided script.
    pub fn substitute_receiver_script(
        self,
        output_script: &Script,
    ) -> Result<Self, OutputSubstitutionError> {
        let inner = self.state.inner.substitute_receiver_script(output_script)?;
        Ok(Receiver { state: WantsOutputs { inner, session_context: self.state.session_context } })
    }

    /// Replaces **all** receiver outputs with the one or more provided `replacement_outputs`, and
    /// sets up the passed `drain_script` as the receiver-owned output which might have its value
    /// adjusted based on the modifications the receiver makes in the subsequent typestates.
    ///
    /// Sender's outputs are not touched. Existing receiver outputs will be replaced with the
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
        let inner = self.state.inner.replace_receiver_outputs(replacement_outputs, drain_script)?;
        Ok(Receiver { state: WantsOutputs { inner, session_context: self.state.session_context } })
    }

    /// Commits the outputs as final, and moves on to the next typestate.
    ///
    /// Outputs cannot be modified after this function is called.
    pub fn commit_outputs(self) -> NextStateTransition<SessionEvent, Receiver<WantsInputs>> {
        let inner = self.state.inner.clone().commit_outputs();
        NextStateTransition::success(
            SessionEvent::WantsInputs(inner.clone()),
            Receiver { state: WantsInputs { inner, session_context: self.state.session_context } },
        )
    }

    pub(crate) fn apply_wants_inputs(self, inner: common::WantsInputs) -> ReceiveSession {
        let new_state =
            Receiver { state: WantsInputs { inner, session_context: self.state.session_context } };
        ReceiveSession::WantsInputs(new_state)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WantsInputs {
    inner: common::WantsInputs,
    session_context: SessionContext,
}

/// Typestate for a checked proposal which the receiver may contribute inputs to.
///
/// Call [`Receiver<WantsInputs>::commit_inputs`] to proceed.
impl Receiver<WantsInputs> {
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
        self.inner.try_preserving_privacy(candidate_inputs)
    }

    /// Contributes the provided list of inputs to the transaction at random indices. If the total input
    /// amount exceeds the total output amount after the contribution, adds all excess amount to
    /// the receiver change output.
    pub fn contribute_inputs(
        self,
        inputs: impl IntoIterator<Item = InputPair>,
    ) -> Result<Self, InputContributionError> {
        let inner = self.state.inner.contribute_inputs(inputs)?;
        Ok(Receiver { state: WantsInputs { inner, session_context: self.state.session_context } })
    }

    /// Commits the inputs as final, and moves on to the next typestate.
    ///
    /// Inputs cannot be modified after this function is called.
    pub fn commit_inputs(self) -> NextStateTransition<SessionEvent, Receiver<WantsFeeRange>> {
        let inner = self.state.inner.clone().commit_inputs();
        NextStateTransition::success(
            SessionEvent::WantsFeeRange(inner.clone()),
            Receiver {
                state: WantsFeeRange { inner, session_context: self.state.session_context },
            },
        )
    }

    pub(crate) fn apply_wants_fee_range(self, inner: common::WantsFeeRange) -> ReceiveSession {
        let new_state = Receiver {
            state: WantsFeeRange { inner, session_context: self.state.session_context },
        };
        ReceiveSession::WantsFeeRange(new_state)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WantsFeeRange {
    inner: common::WantsFeeRange,
    session_context: SessionContext,
}

impl Receiver<WantsFeeRange> {
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
    pub fn apply_fee_range(
        self,
        min_fee_rate: Option<FeeRate>,
        max_effective_fee_rate: Option<FeeRate>,
    ) -> MaybeFatalTransition<SessionEvent, Receiver<ProvisionalProposal>, ProtocolError> {
        let max_effective_fee_rate =
            max_effective_fee_rate.or(Some(self.state.session_context.max_fee_rate));
        let psbt_context = match self
            .state
            .inner
            .calculate_psbt_context_with_fee_range(min_fee_rate, max_effective_fee_rate)
        {
            Ok(inner) => inner,
            Err(e) => {
                // FIXME: follow up by returning a terminal error rather than replyable error
                let payload_error = super::PayloadError::from(e);
                return MaybeFatalTransition::fatal(
                    SessionEvent::SessionInvalid(
                        payload_error.to_string(),
                        Some(JsonReply::from(&payload_error)),
                    ),
                    ProtocolError::OriginalPayload(payload_error),
                );
            }
        };
        MaybeFatalTransition::success(
            SessionEvent::ProvisionalProposal(psbt_context.clone()),
            Receiver {
                state: ProvisionalProposal {
                    psbt_context,
                    session_context: self.state.session_context.clone(),
                },
            },
        )
    }

    pub(crate) fn apply_provisional_proposal(self, psbt_context: PsbtContext) -> ReceiveSession {
        let new_state = Receiver {
            state: ProvisionalProposal {
                psbt_context,
                session_context: self.state.session_context,
            },
        };
        ReceiveSession::ProvisionalProposal(new_state)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProvisionalProposal {
    psbt_context: PsbtContext,
    session_context: SessionContext,
}

/// Typestate for a checked proposal which had both the outputs and the inputs modified
/// by the receiver. The receiver may sign and finalize the Payjoin proposal which will be sent to
/// the sender for their signature.
///
/// Call [`Receiver<ProvisionalProposal>::finalize_proposal`] to return a finalized [`PayjoinProposal`].
impl Receiver<ProvisionalProposal> {
    /// Finalizes the Payjoin proposal into a PSBT which the sender will find acceptable before
    /// they re-sign the transaction and broadcast it to the network.
    ///
    /// Finalization consists of two steps:
    ///   1. Remove all sender signatures which were received with the original PSBT as these signatures are now invalid.
    ///   2. Sign and finalize the resulting PSBT using the passed `wallet_process_psbt` signing function.
    pub fn finalize_proposal(
        self,
        wallet_process_psbt: impl Fn(&Psbt) -> Result<Psbt, ImplementationError>,
    ) -> MaybeTransientTransition<SessionEvent, Receiver<PayjoinProposal>, ImplementationError>
    {
        let inner = match self.state.psbt_context.finalize_proposal(wallet_process_psbt) {
            Ok(inner) => inner,
            Err(e) => {
                return MaybeTransientTransition::transient(e);
            }
        };
        let payjoin_proposal =
            PayjoinProposal { psbt: inner.clone(), session_context: self.state.session_context };
        MaybeTransientTransition::success(
            SessionEvent::PayjoinProposal(inner),
            Receiver { state: payjoin_proposal },
        )
    }

    pub(crate) fn apply_payjoin_proposal(self, psbt: Psbt) -> ReceiveSession {
        let new_state = Receiver {
            state: PayjoinProposal { psbt, session_context: self.state.session_context },
        };
        ReceiveSession::PayjoinProposal(new_state)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PayjoinProposal {
    psbt: Psbt,
    session_context: SessionContext,
}

/// A finalized Payjoin proposal, complete with fees and receiver signatures, that the sender
/// should find acceptable.
impl Receiver<PayjoinProposal> {
    /// The UTXOs that would be spent by this Payjoin transaction.
    pub fn utxos_to_be_locked(&self) -> impl '_ + Iterator<Item = &bitcoin::OutPoint> {
        // TODO: de-duplicate this with the v1 implementation
        // It would make more sense if the payjoin proposal was only available after utxos are locked via session persister
        self.psbt.unsigned_tx.input.iter().map(|input| &input.previous_output)
    }

    /// The Payjoin Proposal PSBT.
    pub fn psbt(&self) -> &Psbt { &self.psbt }

    /// Construct an OHTTP Encapsulated HTTP POST request for the Proposal PSBT
    pub fn create_post_request(
        &mut self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), Error> {
        let target_resource: Url;
        let body: Vec<u8>;
        let method: &str;

        if let Some(e) = &self.session_context.reply_key {
            // Prepare v2 payload
            let payjoin_bytes = self.psbt.serialize();
            let sender_mailbox = short_id_from_pubkey(e);
            target_resource = mailbox_endpoint(&self.session_context.directory, &sender_mailbox);
            body = encrypt_message_b(payjoin_bytes, &self.session_context.receiver_key, e)?;
            method = "POST";
        } else {
            // Prepare v2 wrapped and backwards-compatible v1 payload
            body = self.psbt.to_string().as_bytes().to_vec();
            let receiver_mailbox =
                short_id_from_pubkey(self.session_context.receiver_key.public_key());
            target_resource = mailbox_endpoint(&self.session_context.directory, &receiver_mailbox);
            method = "PUT";
        }
        tracing::debug!("Payjoin PSBT target: {}", target_resource.as_str());
        let (body, ctx) = ohttp_encapsulate(
            &mut self.session_context.ohttp_keys,
            method,
            target_resource.as_str(),
            Some(&body),
        )?;

        let req = Request::new_v2(&self.session_context.full_relay_url(ohttp_relay)?, &body);
        Ok((req, ctx))
    }

    /// Processes the response for the final POST message from the receiver client in the v2 Payjoin protocol.
    ///
    /// This function decapsulates the response using the provided OHTTP context. If the response status is successful,
    /// it indicates that the Payjoin proposal has been accepted. Otherwise, it returns an error with the status code.
    ///
    /// After this function is called, the receiver can either wait for the Payjoin transaction to be broadcast or
    /// choose to broadcast the original PSBT.
    pub fn process_response(
        &self,
        res: &[u8],
        ohttp_context: ohttp::ClientResponse,
    ) -> MaybeSuccessTransition<(), Error> {
        match process_post_res(res, ohttp_context)
            .map_err(|e| InternalSessionError::DirectoryResponse(e).into())
        {
            Ok(_) => MaybeSuccessTransition::success(()),
            Err(e) => MaybeSuccessTransition::transient(e),
        }
    }
}

/// Derive a mailbox endpoint on a directory given a [`ShortId`].
/// It consists of a directory URL and the session ShortID in the path.
fn mailbox_endpoint(directory: &Url, id: &ShortId) -> Url {
    let mut url = directory.clone();
    {
        let mut path_segments =
            url.path_segments_mut().expect("Payjoin Directory URL cannot be a base");
        path_segments.push(&id.to_string());
    }
    url
}

/// Gets the Payjoin URI from a session context
pub(crate) fn pj_uri<'a>(
    session_context: &SessionContext,
    output_substitution: OutputSubstitution,
) -> crate::PjUri<'a> {
    use crate::uri::PayjoinExtras;
    let pj_param = crate::uri::PjParam::V2(crate::uri::v2::PjParam::new(
        session_context.directory.clone(),
        session_context.proposal_mailbox_id(),
        session_context.expiry,
        session_context.ohttp_keys.clone(),
        session_context.receiver_key.public_key().clone(),
    ));
    let extras = PayjoinExtras { pj_param, output_substitution };
    let mut uri = bitcoin_uri::Uri::with_extras(session_context.address.clone(), extras);
    uri.amount = session_context.amount;

    uri
}

#[cfg(test)]
pub mod test {
    use std::str::FromStr;

    use bitcoin::FeeRate;
    use once_cell::sync::Lazy;
    use payjoin_test_utils::{
        BoxError, EXAMPLE_URL, KEM, KEY_ID, ORIGINAL_PSBT, PARSED_ORIGINAL_PSBT, QUERY_PARAMS,
        SYMMETRIC,
    };

    use super::*;
    use crate::output_substitution::OutputSubstitution;
    use crate::persist::{NoopSessionPersister, RejectTransient, Rejection};
    use crate::receive::optional_parameters::Params;
    use crate::receive::v2;
    use crate::ImplementationError;

    pub(crate) static SHARED_CONTEXT: Lazy<SessionContext> = Lazy::new(|| SessionContext {
        address: Address::from_str("tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4")
            .expect("valid address")
            .assume_checked(),
        directory: EXAMPLE_URL.clone(),
        mailbox: None,
        ohttp_keys: OhttpKeys(
            ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).expect("valid key config"),
        ),
        expiry: SystemTime::now() + Duration::from_secs(60),
        receiver_key: HpkeKeyPair::gen_keypair(),
        reply_key: None,
        amount: None,
        max_fee_rate: FeeRate::BROADCAST_MIN,
    });

    pub(crate) fn unchecked_proposal_v2_from_test_vector() -> UncheckedOriginalPayload {
        let pairs = url::form_urlencoded::parse(QUERY_PARAMS.as_bytes());
        let params = Params::from_query_pairs(pairs, &[Version::Two])
            .expect("Test utils query params should not fail");
        UncheckedOriginalPayload {
            original: OriginalPayload { psbt: PARSED_ORIGINAL_PSBT.clone(), params },
            session_context: SessionContext {
                reply_key: Some(HpkeKeyPair::gen_keypair().public_key().clone()),
                ..SHARED_CONTEXT.clone()
            },
        }
    }

    pub(crate) fn maybe_inputs_owned_v2_from_test_vector() -> MaybeInputsOwned {
        let pairs = url::form_urlencoded::parse(QUERY_PARAMS.as_bytes());
        let params = Params::from_query_pairs(pairs, &[Version::Two])
            .expect("Test utils query params should not fail");
        MaybeInputsOwned {
            original: OriginalPayload { psbt: PARSED_ORIGINAL_PSBT.clone(), params },
            session_context: SessionContext {
                reply_key: Some(HpkeKeyPair::gen_keypair().public_key().clone()),
                ..SHARED_CONTEXT.clone()
            },
        }
    }

    pub(crate) fn mock_err() -> (String, JsonReply) {
        let noop_persister = NoopSessionPersister::default();
        let receiver = Receiver { state: unchecked_proposal_v2_from_test_vector() };
        let server_error = || {
            receiver
                .clone()
                .check_broadcast_suitability(None, |_| Err("mock error".into()))
                .save(&noop_persister)
        };

        let error = server_error().expect_err("Server error should be populated with mock error");
        let res = error.api_error().expect("check_broadcast error should propagate to api error");
        let actual_json = JsonReply::from(&res);
        (res.to_string(), actual_json)
    }

    #[test]
    fn test_v2_mutable_receiver_state_closures() {
        let persister = NoopSessionPersister::default();
        let mut call_count = 0;
        let maybe_inputs_owned = maybe_inputs_owned_v2_from_test_vector();
        let receiver = v2::Receiver { state: maybe_inputs_owned };

        fn mock_callback(call_count: &mut usize, ret: bool) -> Result<bool, ImplementationError> {
            *call_count += 1;
            Ok(ret)
        }

        let maybe_inputs_seen =
            receiver.check_inputs_not_owned(&mut |_| mock_callback(&mut call_count, false));
        assert_eq!(call_count, 1);

        let outputs_unknown = maybe_inputs_seen
            .save(&persister)
            .expect("Noop persister shouldn't fail")
            .check_no_inputs_seen_before(&mut |_| mock_callback(&mut call_count, false))
            .save(&persister)
            .expect("Noop persister shouldn't fail");
        assert_eq!(call_count, 2);

        let _wants_outputs = outputs_unknown
            .identify_receiver_outputs(&mut |_| mock_callback(&mut call_count, true));
        // there are 2 receiver outputs so we should expect this callback to run twice incrementing
        // call count twice
        assert_eq!(call_count, 4);
    }

    #[test]
    fn test_unchecked_proposal_transient_error() -> Result<(), BoxError> {
        let unchecked_proposal = unchecked_proposal_v2_from_test_vector();
        let receiver = v2::Receiver { state: unchecked_proposal };

        let unchecked_proposal = receiver.check_broadcast_suitability(Some(FeeRate::MIN), |_| {
            Err(ImplementationError::new(Error::Implementation("mock error".into())))
        });

        match unchecked_proposal {
            MaybeFatalTransition(Err(Rejection::Transient(RejectTransient(
                Error::Implementation(error),
            )))) => assert_eq!(
                error.to_string(),
                Error::Implementation("mock error".into()).to_string()
            ),
            _ => panic!("Expected ReplyableError but got unexpected error or Ok"),
        }

        Ok(())
    }

    #[test]
    fn test_maybe_inputs_seen_transient_error() -> Result<(), BoxError> {
        let persister = NoopSessionPersister::default();
        let unchecked_proposal = unchecked_proposal_v2_from_test_vector();
        let receiver = v2::Receiver { state: unchecked_proposal };

        let maybe_inputs_owned = receiver
            .assume_interactive_receiver()
            .save(&persister)
            .expect("Noop persister shouldn't fail");
        let maybe_inputs_seen = maybe_inputs_owned.check_inputs_not_owned(&mut |_| {
            Err(ImplementationError::new(Error::Implementation("mock error".into())))
        });

        match maybe_inputs_seen {
            MaybeFatalTransition(Err(Rejection::Transient(RejectTransient(
                Error::Implementation(error),
            )))) => assert_eq!(
                error.to_string(),
                Error::Implementation("mock error".into()).to_string()
            ),
            _ => panic!("Expected ReplyableError but got unexpected error or Ok"),
        }

        Ok(())
    }

    #[test]
    fn test_outputs_unknown_transient_error() -> Result<(), BoxError> {
        let persister = NoopSessionPersister::default();
        let unchecked_proposal = unchecked_proposal_v2_from_test_vector();
        let receiver = v2::Receiver { state: unchecked_proposal };

        let maybe_inputs_owned = receiver
            .assume_interactive_receiver()
            .save(&persister)
            .expect("Noop persister shouldn't fail");
        let maybe_inputs_seen = maybe_inputs_owned
            .check_inputs_not_owned(&mut |_| Ok(false))
            .save(&persister)
            .expect("Noop persister shouldn't fail");
        let outputs_unknown = maybe_inputs_seen.check_no_inputs_seen_before(&mut |_| {
            Err(ImplementationError::new(Error::Implementation("mock error".into())))
        });
        match outputs_unknown {
            MaybeFatalTransition(Err(Rejection::Transient(RejectTransient(
                Error::Implementation(error),
            )))) => assert_eq!(
                error.to_string(),
                Error::Implementation("mock error".into()).to_string()
            ),
            _ => panic!("Expected ReplyableError but got unexpected error or Ok"),
        }

        Ok(())
    }

    #[test]
    fn test_wants_outputs_transient_error() -> Result<(), BoxError> {
        let persister = NoopSessionPersister::default();
        let unchecked_proposal = unchecked_proposal_v2_from_test_vector();
        let receiver = v2::Receiver { state: unchecked_proposal };

        let maybe_inputs_owned = receiver
            .assume_interactive_receiver()
            .save(&persister)
            .expect("Noop persister shouldn't fail");
        let maybe_inputs_seen = maybe_inputs_owned
            .check_inputs_not_owned(&mut |_| Ok(false))
            .save(&persister)
            .expect("Noop persister should not fail");
        let outputs_unknown = maybe_inputs_seen
            .check_no_inputs_seen_before(&mut |_| Ok(false))
            .save(&persister)
            .expect("Noop persister should not fail");
        let wants_outputs = outputs_unknown.identify_receiver_outputs(&mut |_| {
            Err(ImplementationError::new(Error::Implementation("mock error".into())))
        });
        match wants_outputs {
            MaybeFatalTransition(Err(Rejection::Transient(RejectTransient(
                Error::Implementation(error),
            )))) => assert_eq!(
                error.to_string(),
                Error::Implementation("mock error".into()).to_string()
            ),
            _ => panic!("Expected ReplyableError but got unexpected error or Ok"),
        }

        Ok(())
    }

    #[test]
    fn test_extract_err_req() -> Result<(), BoxError> {
        let receiver = Receiver { state: unchecked_proposal_v2_from_test_vector() };
        let mock_err = mock_err();
        let expected_json = serde_json::json!({
            "errorCode": "unavailable",
            "message": "Receiver error"
        });

        assert_eq!(mock_err.1.to_json(), expected_json);

        let (_req, _ctx) = extract_err_req(&mock_err.1, &*EXAMPLE_URL, &receiver.session_context)?;

        let internal_error: Error = InternalPayloadError::MissingPayment.into();
        let (_req, _ctx) =
            extract_err_req(&(&internal_error).into(), &*EXAMPLE_URL, &receiver.session_context)?;
        Ok(())
    }

    #[test]
    fn test_extract_err_req_expiry() -> Result<(), BoxError> {
        let now = SystemTime::now();
        let noop_persister = NoopSessionPersister::default();
        let context = SessionContext { expiry: now, ..SHARED_CONTEXT.clone() };
        let receiver = Receiver {
            state: UncheckedOriginalPayload {
                original: crate::receive::tests::original_from_test_vector(),
                session_context: context.clone(),
            },
        };

        let server_error = || {
            receiver
                .clone()
                .check_broadcast_suitability(None, |_| Err("mock error".into()))
                .save(&noop_persister)
        };

        let error = server_error().expect_err("Server error should be populated with mock error");
        let res = error.api_error().expect("check_broadcast error should propagate to api error");
        let actual_json = JsonReply::from(&res);

        let expiry = extract_err_req(&actual_json, &*EXAMPLE_URL, &context);

        match expiry {
            Err(error) => assert_eq!(
                error.to_string(),
                SessionError::from(InternalSessionError::Expired(now)).to_string()
            ),
            Ok(_) => panic!("Expected session expiry error, got success"),
        }
        Ok(())
    }

    #[test]
    fn default_expiry() {
        let now = SystemTime::now();
        let noop_persister = NoopSessionPersister::default();

        let session = ReceiverBuilder::new(
            SHARED_CONTEXT.address.clone(),
            SHARED_CONTEXT.directory.clone(),
            SHARED_CONTEXT.ohttp_keys.clone(),
        )
        .expect("constructor on test vector should not fail")
        .build()
        .save(&noop_persister)
        .expect("Noop persister shouldn't fail");
        let session_expiry = session.context.expiry.duration_since(now).unwrap().as_secs();
        let default_expiry = Duration::from_secs(86400);
        if let Some(expected_expiry) = now.checked_add(default_expiry) {
            assert_eq!(TWENTY_FOUR_HOURS_DEFAULT_EXPIRY, default_expiry);
            assert_eq!(session_expiry, expected_expiry.duration_since(now).unwrap().as_secs());
        }
    }

    #[test]
    fn default_max_fee_rate() {
        let noop_persister = NoopSessionPersister::default();
        let receiver = ReceiverBuilder::new(
            SHARED_CONTEXT.address.clone(),
            SHARED_CONTEXT.directory.clone(),
            SHARED_CONTEXT.ohttp_keys.clone(),
        )
        .expect("constructor on test vector should not fail")
        .build()
        .save(&noop_persister)
        .expect("Noop persister shouldn't fail");

        assert_eq!(receiver.context.max_fee_rate, FeeRate::BROADCAST_MIN);

        let non_default_max_fee_rate =
            FeeRate::from_sat_per_vb(1000).expect("Fee rate should be valid");
        let receiver = ReceiverBuilder::new(
            SHARED_CONTEXT.address.clone(),
            SHARED_CONTEXT.directory.clone(),
            SHARED_CONTEXT.ohttp_keys.clone(),
        )
        .expect("constructor on test vector should not fail")
        .with_max_fee_rate(non_default_max_fee_rate)
        .build()
        .save(&noop_persister)
        .expect("Noop persister shouldn't fail");
        assert_eq!(receiver.context.max_fee_rate, non_default_max_fee_rate);
    }

    #[test]
    fn build_receiver_with_non_default_expiry() {
        let now = SystemTime::now();
        let expiry = Duration::from_secs(60);
        let noop_persister = NoopSessionPersister::default();
        let receiver = ReceiverBuilder::new(
            SHARED_CONTEXT.address.clone(),
            SHARED_CONTEXT.directory.clone(),
            SHARED_CONTEXT.ohttp_keys.clone(),
        )
        .expect("constructor on test vector should not fail")
        .with_expiry(expiry)
        .build()
        .save(&noop_persister)
        .expect("Noop persister shouldn't fail");
        assert_eq!(
            receiver.context.expiry.duration_since(now).unwrap().as_secs(),
            expiry.as_secs()
        );
    }

    #[test]
    fn test_v2_pj_uri() {
        let uri = Receiver { state: Initialized { context: SHARED_CONTEXT.clone() } }.pj_uri();
        assert_ne!(uri.extras.pj_param.endpoint(), EXAMPLE_URL.clone());
        assert_eq!(uri.extras.output_substitution, OutputSubstitution::Disabled);
    }

    #[test]
    /// Ensures output substitution is disabled for v1 proposals in v2 logic.
    fn test_unchecked_from_payload_disables_output_substitution_for_v1() {
        let base64 = ORIGINAL_PSBT;
        let query = "v=1";
        let payload = format!("{base64}\n{query}");
        let mut receiver = Receiver { state: Initialized { context: SHARED_CONTEXT.clone() } };
        let proposal = receiver
            .unchecked_from_payload(&payload)
            .expect("unchecked_from_payload should parse valid v1 PSBT payload");
        assert_eq!(proposal.params.output_substitution, OutputSubstitution::Disabled);
    }
}
