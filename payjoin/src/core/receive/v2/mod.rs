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
use bitcoin::{Address, FeeRate, OutPoint, Script, TxOut};
pub(crate) use error::InternalSessionError;
pub use error::SessionError;
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use session::InternalReplayError;
pub use session::{replay_event_log, ReplayError, SessionEvent, SessionHistory};
use url::Url;

use super::error::{Error, InputContributionError};
use super::{
    v1, InternalPayloadError, JsonReply, OutputSubstitutionError, ReplyableError, SelectionError,
};
use crate::hpke::{decrypt_message_a, encrypt_message_b, HpkeKeyPair, HpkePublicKey};
use crate::ohttp::{
    ohttp_encapsulate, process_get_res, process_post_res, OhttpEncapsulationError, OhttpKeys,
};
use crate::output_substitution::OutputSubstitution;
use crate::persist::{
    MaybeBadInitInputsTransition, MaybeFatalTransition, MaybeFatalTransitionWithNoResults,
    MaybeSuccessTransition, MaybeTransientTransition, NextStateTransition,
};
use crate::receive::{parse_payload, InputPair};
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
    subdirectory: Option<url::Url>,
    ohttp_keys: OhttpKeys,
    expiry: SystemTime,
    s: HpkeKeyPair,
    e: Option<HpkePublicKey>,
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

    /// The per-session identifier
    pub(crate) fn id(&self) -> ShortId {
        sha256::Hash::hash(&self.s.public_key().to_compressed_bytes()).into()
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

fn subdir_path_from_pubkey(pubkey: &HpkePublicKey) -> ShortId {
    sha256::Hash::hash(&pubkey.to_compressed_bytes()).into()
}

/// Represents the various states of a Payjoin receiver session during the protocol flow.
/// Each variant parameterizes a `Receiver` with a specific state type, except for [`ReceiveSession::Uninitialized`] which
/// has no context yet and [`ReceiveSession::TerminalFailure`] which indicates the session has ended or is invalid.
///
/// This provides type erasure for the receive session state, allowing for the session to be replayed
/// and the state to be updated with the next event over a uniform interface.
#[derive(Debug, Clone, PartialEq)]
pub enum ReceiveSession {
    Uninitialized(Receiver<UninitializedReceiver>),
    Initialized(Receiver<Initialized>),
    UncheckedProposal(Receiver<UncheckedProposal>),
    MaybeInputsOwned(Receiver<MaybeInputsOwned>),
    MaybeInputsSeen(Receiver<MaybeInputsSeen>),
    OutputsUnknown(Receiver<OutputsUnknown>),
    WantsOutputs(Receiver<WantsOutputs>),
    WantsInputs(Receiver<WantsInputs>),
    ProvisionalProposal(Receiver<ProvisionalProposal>),
    PayjoinProposal(Receiver<PayjoinProposal>),
    TerminalFailure,
}

impl ReceiveSession {
    fn process_event(self, event: SessionEvent) -> Result<ReceiveSession, ReplayError> {
        match (self, event) {
            (ReceiveSession::Uninitialized(_), SessionEvent::Created(context)) =>
                Ok(ReceiveSession::Initialized(Receiver { state: Initialized { context } })),

            (
                ReceiveSession::Initialized(state),
                SessionEvent::UncheckedProposal((proposal, reply_key)),
            ) => Ok(state.apply_unchecked_from_payload(proposal, reply_key)?),

            (ReceiveSession::UncheckedProposal(state), SessionEvent::MaybeInputsOwned(inputs)) =>
                Ok(state.apply_maybe_inputs_owned(inputs)),

            (
                ReceiveSession::MaybeInputsOwned(state),
                SessionEvent::MaybeInputsSeen(maybe_inputs_seen),
            ) => Ok(state.apply_maybe_inputs_seen(maybe_inputs_seen)),

            (
                ReceiveSession::MaybeInputsSeen(state),
                SessionEvent::OutputsUnknown(outputs_unknown),
            ) => Ok(state.apply_outputs_unknown(outputs_unknown)),

            (ReceiveSession::OutputsUnknown(state), SessionEvent::WantsOutputs(wants_outputs)) =>
                Ok(state.apply_wants_outputs(wants_outputs)),

            (ReceiveSession::WantsOutputs(state), SessionEvent::WantsInputs(wants_inputs)) =>
                Ok(state.apply_wants_inputs(wants_inputs)),

            (
                ReceiveSession::WantsInputs(state),
                SessionEvent::ProvisionalProposal(provisional_proposal),
            ) => Ok(state.apply_provisional_proposal(provisional_proposal)),

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

/// Any typestate should implement this trait to be considered a part of the protocol flow.
///
/// **IMPORTANT**: This is only meant to be implemented within the crate. It should not be used by dependencies
/// to extend the flow with new custom typestates.
///
/// TODO: Make this sealed (<https://github.com/payjoin/rust-payjoin/issues/747>).
pub trait State {}

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

/// Extract an OHTTP Encapsulated HTTP POST request to return
/// a Receiver Error Response
fn extract_err_req(
    err: &JsonReply,
    ohttp_relay: impl IntoUrl,
    session_context: &SessionContext,
) -> Result<(Request, ohttp::ClientResponse), SessionError> {
    if SystemTime::now() > session_context.expiry {
        return Err(InternalSessionError::Expired(session_context.expiry).into());
    }
    let subdir = subdir(&session_context.directory, &session_context.id());
    let (body, ohttp_ctx) = ohttp_encapsulate(
        &mut session_context.ohttp_keys.0.clone(),
        "POST",
        subdir.as_str(),
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

#[derive(Debug, Clone, PartialEq)]
/// The receiver is not initialized yet, no session context is available yet
pub struct UninitializedReceiver {}

impl State for UninitializedReceiver {}

impl Receiver<UninitializedReceiver> {
    /// Creates a new [`Receiver<Initialized>`] with the provided parameters.
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
    pub fn create_session(
        address: Address,
        directory: impl IntoUrl,
        ohttp_keys: OhttpKeys,
        expire_after: Option<Duration>,
    ) -> MaybeBadInitInputsTransition<SessionEvent, Receiver<Initialized>, IntoUrlError> {
        let directory = match directory.into_url() {
            Ok(url) => url,
            Err(e) => return MaybeBadInitInputsTransition::bad_init_inputs(e),
        };

        let session_context = SessionContext {
            address,
            directory,
            subdirectory: None,
            ohttp_keys,
            expiry: SystemTime::now() + expire_after.unwrap_or(TWENTY_FOUR_HOURS_DEFAULT_EXPIRY),
            s: HpkeKeyPair::gen_keypair(),
            e: None,
        };
        MaybeBadInitInputsTransition::success(
            SessionEvent::Created(session_context.clone()),
            Receiver { state: Initialized { context: session_context } },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Initialized {
    context: SessionContext,
}

impl State for Initialized {}

impl Receiver<Initialized> {
    /// Extract an OHTTP Encapsulated HTTP GET request for the Original PSBT
    pub fn extract_req(
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

    /// The response can either be an UncheckedProposal or an ACCEPTED message
    /// indicating no UncheckedProposal is available yet.
    pub fn process_res(
        &mut self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> MaybeFatalTransitionWithNoResults<
        SessionEvent,
        Receiver<UncheckedProposal>,
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

        if let Some(proposal) = proposal {
            MaybeFatalTransitionWithNoResults::success(
                SessionEvent::UncheckedProposal((proposal.clone(), self.context.e.clone())),
                Receiver {
                    state: UncheckedProposal { v1: proposal, context: self.state.context.clone() },
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
    ) -> Result<Option<v1::UncheckedProposal>, Error> {
        let body = match process_get_res(body, context)
            .map_err(InternalSessionError::DirectoryResponse)?
        {
            Some(body) => body,
            None => return Ok(None),
        };
        match std::str::from_utf8(&body) {
            // V1 response bodies are utf8 plaintext
            Ok(response) => Ok(Some(self.extract_proposal_from_v1(response)?)),
            // V2 response bodies are encrypted binary
            Err(_) => Ok(Some(self.extract_proposal_from_v2(body)?)),
        }
    }

    fn fallback_req_body(
        &mut self,
    ) -> Result<
        ([u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES], ohttp::ClientResponse),
        OhttpEncapsulationError,
    > {
        let fallback_target = subdir(&self.context.directory, &self.context.id());
        ohttp_encapsulate(&mut self.context.ohttp_keys, "GET", fallback_target.as_str(), None)
    }

    fn extract_proposal_from_v1(
        &mut self,
        response: &str,
    ) -> Result<v1::UncheckedProposal, ReplyableError> {
        self.unchecked_from_payload(response)
    }

    fn extract_proposal_from_v2(
        &mut self,
        response: Vec<u8>,
    ) -> Result<v1::UncheckedProposal, Error> {
        let (payload_bytes, e) = decrypt_message_a(&response, self.context.s.secret_key().clone())?;
        self.context.e = Some(e);
        let payload = std::str::from_utf8(&payload_bytes)
            .map_err(|e| Error::ReplyToSender(InternalPayloadError::Utf8(e).into()))?;
        self.unchecked_from_payload(payload).map_err(Error::ReplyToSender)
    }

    fn unchecked_from_payload(
        &mut self,
        payload: &str,
    ) -> Result<v1::UncheckedProposal, ReplyableError> {
        let (base64, padded_query) = payload.split_once('\n').unwrap_or_default();
        let query = padded_query.trim_matches('\0');
        log::trace!("Received query: {query}, base64: {base64}"); // my guess is no \n so default is wrong
        let (psbt, mut params) =
            parse_payload(base64, query, SUPPORTED_VERSIONS).map_err(ReplyableError::Payload)?;

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

            // Additionally V1 sessions never have an optimistic merge opportunity
            #[cfg(feature = "_multiparty")]
            {
                params.optimistic_merge = false;
            }
        }

        let inner = v1::UncheckedProposal { psbt, params };
        Ok(inner)
    }

    /// Build a V2 Payjoin URI from the receiver's context
    pub fn pj_uri<'a>(&self) -> crate::PjUri<'a> {
        pj_uri(&self.context, OutputSubstitution::Disabled)
    }

    pub(crate) fn apply_unchecked_from_payload(
        self,
        event: v1::UncheckedProposal,
        reply_key: Option<HpkePublicKey>,
    ) -> Result<ReceiveSession, InternalReplayError> {
        if self.state.context.expiry < SystemTime::now() {
            // Session is expired, close the session
            return Err(InternalReplayError::SessionExpired(self.state.context.expiry));
        }

        let new_state = Receiver {
            state: UncheckedProposal {
                v1: event,
                context: SessionContext { e: reply_key, ..self.state.context },
            },
        };

        Ok(ReceiveSession::UncheckedProposal(new_state))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct UncheckedProposal {
    pub(crate) v1: v1::UncheckedProposal,
    pub(crate) context: SessionContext,
}

impl State for UncheckedProposal {}

/// The original PSBT and the optional parameters received from the sender.
///
/// This is the first typestate after the retrieval of the sender's original proposal in
/// the receiver's workflow. At this stage, the receiver can verify that the original PSBT they have
/// received from the sender is broadcastable to the network in the case of a payjoin failure.
///
/// The recommended usage of this typestate differs based on whether you are implementing an
/// interactive (where the receiver takes manual actions to respond to the
/// payjoin proposal) or a non-interactive (ex. a donation page which automatically generates a new QR code
/// for each visit) payment receiver. For the latter, you should call [`Receiver<UncheckedProposal>::check_broadcast_suitability`] to check
/// that the proposal is actually broadcastable (and, optionally, whether the fee rate is above the
/// minimum limit you have set). These mechanisms protect the receiver against probing attacks, where
/// a malicious sender can repeatedly send proposals to have the non-interactive receiver reveal the UTXOs
/// it owns with the proposals it modifies.
///
/// If you are implementing an interactive payment receiver, then such checks are not necessary, and you
/// can go ahead with calling [`Receiver<UncheckedProposal>::assume_interactive_receiver`] to move on to the next typestate.
impl Receiver<UncheckedProposal> {
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
    ) -> MaybeFatalTransition<SessionEvent, Receiver<MaybeInputsOwned>, ReplyableError> {
        let inner =
            match self.state.v1.clone().check_broadcast_suitability(min_fee_rate, can_broadcast) {
                Ok(v1) => v1,
                Err(e) => match e {
                    ReplyableError::Implementation(_) => return MaybeFatalTransition::transient(e),
                    _ =>
                        return MaybeFatalTransition::fatal(
                            SessionEvent::SessionInvalid(e.to_string(), Some(JsonReply::from(&e))),
                            e,
                        ),
                },
            };
        MaybeFatalTransition::success(
            SessionEvent::MaybeInputsOwned(inner.clone()),
            Receiver { state: MaybeInputsOwned { v1: inner, context: self.context.clone() } },
        )
    }

    /// Moves on to the next typestate without any of the current typestate's validations.
    ///
    /// Use this for interactive payment receivers, where there is no risk of a probing attack since the
    /// receiver needs to manually create payjoin URIs.
    pub fn assume_interactive_receiver(
        self,
    ) -> NextStateTransition<SessionEvent, Receiver<MaybeInputsOwned>> {
        let inner = self.state.v1.assume_interactive_receiver();
        NextStateTransition::success(
            SessionEvent::MaybeInputsOwned(inner.clone()),
            Receiver { state: MaybeInputsOwned { v1: inner, context: self.state.context } },
        )
    }

    pub(crate) fn apply_maybe_inputs_owned(self, v1: v1::MaybeInputsOwned) -> ReceiveSession {
        let new_state = Receiver { state: MaybeInputsOwned { v1, context: self.state.context } };
        ReceiveSession::MaybeInputsOwned(new_state)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MaybeInputsOwned {
    v1: v1::MaybeInputsOwned,
    context: SessionContext,
}

impl State for MaybeInputsOwned {}

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
        self.v1.extract_tx_to_schedule_broadcast()
    }

    /// Check that the original PSBT has no receiver-owned inputs.
    ///
    /// An attacker can try to spend the receiver's own inputs. This check prevents that.
    pub fn check_inputs_not_owned(
        self,
        is_owned: impl Fn(&Script) -> Result<bool, ImplementationError>,
    ) -> MaybeFatalTransition<SessionEvent, Receiver<MaybeInputsSeen>, ReplyableError> {
        let inner = match self.state.v1.clone().check_inputs_not_owned(is_owned) {
            Ok(inner) => inner,
            Err(e) => match e {
                ReplyableError::Implementation(_) => {
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
            SessionEvent::MaybeInputsSeen(inner.clone()),
            Receiver { state: MaybeInputsSeen { v1: inner, context: self.state.context } },
        )
    }

    pub(crate) fn apply_maybe_inputs_seen(self, v1: v1::MaybeInputsSeen) -> ReceiveSession {
        let new_state = Receiver { state: MaybeInputsSeen { v1, context: self.state.context } };
        ReceiveSession::MaybeInputsSeen(new_state)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MaybeInputsSeen {
    v1: v1::MaybeInputsSeen,
    context: SessionContext,
}

impl State for MaybeInputsSeen {}

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
        is_known: impl Fn(&OutPoint) -> Result<bool, ImplementationError>,
    ) -> MaybeFatalTransition<SessionEvent, Receiver<OutputsUnknown>, ReplyableError> {
        let inner = match self.state.v1.clone().check_no_inputs_seen_before(is_known) {
            Ok(inner) => inner,
            Err(e) => match e {
                ReplyableError::Implementation(_) => {
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
            SessionEvent::OutputsUnknown(inner.clone()),
            Receiver { state: OutputsUnknown { inner, context: self.state.context } },
        )
    }

    pub(crate) fn apply_outputs_unknown(self, inner: v1::OutputsUnknown) -> ReceiveSession {
        let new_state = Receiver { state: OutputsUnknown { inner, context: self.state.context } };
        ReceiveSession::OutputsUnknown(new_state)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OutputsUnknown {
    inner: v1::OutputsUnknown,
    context: SessionContext,
}

impl State for OutputsUnknown {}

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
        is_receiver_output: impl Fn(&Script) -> Result<bool, ImplementationError>,
    ) -> MaybeFatalTransition<SessionEvent, Receiver<WantsOutputs>, ReplyableError> {
        let inner = match self.state.inner.clone().identify_receiver_outputs(is_receiver_output) {
            Ok(inner) => inner,
            Err(e) => match e {
                ReplyableError::Implementation(_) => {
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
            SessionEvent::WantsOutputs(inner.clone()),
            Receiver { state: WantsOutputs { v1: inner, context: self.state.context } },
        )
    }

    pub(crate) fn apply_wants_outputs(self, v1: v1::WantsOutputs) -> ReceiveSession {
        let new_state = Receiver { state: WantsOutputs { v1, context: self.state.context } };
        ReceiveSession::WantsOutputs(new_state)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WantsOutputs {
    v1: v1::WantsOutputs,
    context: SessionContext,
}

impl State for WantsOutputs {}

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
    pub fn output_substitution(&self) -> OutputSubstitution { self.v1.output_substitution() }

    /// Substitute the receiver output script with the provided script.
    pub fn substitute_receiver_script(
        self,
        output_script: &Script,
    ) -> Result<Self, OutputSubstitutionError> {
        let inner = self.state.v1.substitute_receiver_script(output_script)?;
        Ok(Receiver { state: WantsOutputs { v1: inner, context: self.state.context } })
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
        let inner = self.state.v1.replace_receiver_outputs(replacement_outputs, drain_script)?;
        Ok(Receiver { state: WantsOutputs { v1: inner, context: self.state.context } })
    }

    /// Commits the outputs as final, and moves on to the next typestate.
    ///
    /// Outputs cannot be modified after this function is called.
    pub fn commit_outputs(self) -> NextStateTransition<SessionEvent, Receiver<WantsInputs>> {
        let inner = self.state.v1.clone().commit_outputs();
        NextStateTransition::success(
            SessionEvent::WantsInputs(inner.clone()),
            Receiver { state: WantsInputs { v1: inner, context: self.state.context } },
        )
    }

    pub(crate) fn apply_wants_inputs(self, v1: v1::WantsInputs) -> ReceiveSession {
        let new_state = Receiver { state: WantsInputs { v1, context: self.state.context } };
        ReceiveSession::WantsInputs(new_state)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WantsInputs {
    v1: v1::WantsInputs,
    context: SessionContext,
}

impl State for WantsInputs {}

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
        self.v1.try_preserving_privacy(candidate_inputs)
    }

    /// Contributes the provided list of inputs to the transaction at random indices. If the total input
    /// amount exceeds the total output amount after the contribution, adds all excess amount to
    /// the receiver change output.
    pub fn contribute_inputs(
        self,
        inputs: impl IntoIterator<Item = InputPair>,
    ) -> Result<Self, InputContributionError> {
        let inner = self.state.v1.contribute_inputs(inputs)?;
        Ok(Receiver { state: WantsInputs { v1: inner, context: self.state.context } })
    }

    /// Commits the inputs as final, and moves on to the next typestate.
    ///
    /// Inputs cannot be modified after this function is called.
    pub fn commit_inputs(self) -> NextStateTransition<SessionEvent, Receiver<ProvisionalProposal>> {
        let inner = self.state.v1.clone().commit_inputs();
        NextStateTransition::success(
            SessionEvent::ProvisionalProposal(inner.clone()),
            Receiver { state: ProvisionalProposal { v1: inner, context: self.state.context } },
        )
    }

    pub(crate) fn apply_provisional_proposal(self, v1: v1::ProvisionalProposal) -> ReceiveSession {
        let new_state = Receiver { state: ProvisionalProposal { v1, context: self.state.context } };
        ReceiveSession::ProvisionalProposal(new_state)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProvisionalProposal {
    v1: v1::ProvisionalProposal,
    context: SessionContext,
}

impl State for ProvisionalProposal {}

/// Typestate for a checked proposal which had both the outputs and the inputs modified
/// by the receiver. The receiver may sign and finalize the Payjoin proposal which will be sent to
/// the sender for their signature.
///
/// Call [`Receiver<ProvisionalProposal>::finalize_proposal`] to return a finalized [`PayjoinProposal`].
impl Receiver<ProvisionalProposal> {
    /// Finalizes the Payjoin proposal into a PSBT which the sender will find acceptable before
    /// they re-sign the transaction and broadcast it to the network.
    ///
    /// Finalization consists of multiple steps:
    ///   1. Apply additional fees to pay for increased weight from any new inputs and/or outputs.
    ///   2. Remove all sender signatures which were received with the original PSBT as these signatures are now invalid.
    ///   3. Sign and finalize the resulting PSBT using the passed `wallet_process_psbt` signing function.
    ///
    /// How much the receiver ends up paying for fees depends on how much the sender stated they
    /// were willing to pay in the parameters of the original proposal. For additional
    /// inputs, fees will be subtracted from the sender's outputs as much as possible until we hit
    /// the limit the sender specified in the Payjoin parameters. Any remaining fees for the new inputs
    /// will be then subtracted from the change output of the receiver.
    ///
    /// Fees for additional outputs are always subtracted from the receiver's outputs.
    ///
    /// The minimum effective fee limit is the highest of the minimum limit set by the sender in
    /// the original proposal parameters and the limit passed in the `min_fee_rate` parameter.
    ///
    /// Errors if the final effective fee rate exceeds `max_effective_fee_rate`.
    pub fn finalize_proposal(
        self,
        wallet_process_psbt: impl Fn(&Psbt) -> Result<Psbt, ImplementationError>,
        min_fee_rate: Option<FeeRate>,
        max_effective_fee_rate: Option<FeeRate>,
    ) -> MaybeTransientTransition<SessionEvent, Receiver<PayjoinProposal>, ReplyableError> {
        let inner = match self.state.v1.clone().finalize_proposal(
            wallet_process_psbt,
            min_fee_rate,
            max_effective_fee_rate,
        ) {
            Ok(inner) => inner,
            Err(e) => {
                // v1::finalize_proposal returns a ReplyableError but the only error that can be returned is ImplementationError from the closure
                // And that is a transient error
                return MaybeTransientTransition::transient(e);
            }
        };
        MaybeTransientTransition::success(
            SessionEvent::PayjoinProposal(inner.clone()),
            Receiver { state: PayjoinProposal { v1: inner, context: self.state.context } },
        )
    }

    pub(crate) fn apply_payjoin_proposal(self, v1: v1::PayjoinProposal) -> ReceiveSession {
        let new_state = Receiver { state: PayjoinProposal { v1, context: self.state.context } };
        ReceiveSession::PayjoinProposal(new_state)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PayjoinProposal {
    v1: v1::PayjoinProposal,
    context: SessionContext,
}

impl State for PayjoinProposal {}

impl PayjoinProposal {
    #[cfg(feature = "_multiparty")]
    // TODO hack to get multi party working. A better solution would be to allow extract_req to be separate from the rest of the v2 context
    pub(crate) fn new(v1: v1::PayjoinProposal, context: SessionContext) -> Self {
        Self { v1, context }
    }
}

/// A finalized Payjoin proposal, complete with fees and receiver signatures, that the sender
/// should find acceptable.
impl Receiver<PayjoinProposal> {
    #[cfg(feature = "_multiparty")]
    pub(crate) fn new(proposal: PayjoinProposal) -> Self { Receiver { state: proposal } }

    /// The UTXOs that would be spent by this Payjoin transaction.
    pub fn utxos_to_be_locked(&self) -> impl '_ + Iterator<Item = &bitcoin::OutPoint> {
        self.v1.utxos_to_be_locked()
    }

    /// The Payjoin Proposal PSBT.
    pub fn psbt(&self) -> &Psbt { self.v1.psbt() }

    /// Extract an OHTTP Encapsulated HTTP POST request for the Proposal PSBT
    pub fn extract_req(
        &mut self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), Error> {
        let target_resource: Url;
        let body: Vec<u8>;
        let method: &str;

        if let Some(e) = &self.context.e {
            // Prepare v2 payload
            let payjoin_bytes = self.v1.psbt().serialize();
            let sender_subdir = subdir_path_from_pubkey(e);
            target_resource = self
                .context
                .directory
                .join(&sender_subdir.to_string())
                .map_err(|e| ReplyableError::Implementation(e.into()))?;
            body = encrypt_message_b(payjoin_bytes, &self.context.s, e)?;
            method = "POST";
        } else {
            // Prepare v2 wrapped and backwards-compatible v1 payload
            body = self.v1.psbt().to_string().as_bytes().to_vec();
            let receiver_subdir = subdir_path_from_pubkey(self.context.s.public_key());
            target_resource = self
                .context
                .directory
                .join(&receiver_subdir.to_string())
                .map_err(|e| ReplyableError::Implementation(e.into()))?;
            method = "PUT";
        }
        log::debug!("Payjoin PSBT target: {}", target_resource.as_str());
        let (body, ctx) = ohttp_encapsulate(
            &mut self.context.ohttp_keys,
            method,
            target_resource.as_str(),
            Some(&body),
        )?;

        let req = Request::new_v2(&self.context.full_relay_url(ohttp_relay)?, &body);
        Ok((req, ctx))
    }

    /// Processes the response for the final POST message from the receiver client in the v2 Payjoin protocol.
    ///
    /// This function decapsulates the response using the provided OHTTP context. If the response status is successful,
    /// it indicates that the Payjoin proposal has been accepted. Otherwise, it returns an error with the status code.
    ///
    /// After this function is called, the receiver can either wait for the Payjoin transaction to be broadcast or
    /// choose to broadcast the original PSBT.
    pub fn process_res(
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

/// The subdirectory for this Payjoin receiver session.
/// It consists of a directory URL and the session ShortID in the path.
fn subdir(directory: &Url, id: &ShortId) -> Url {
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
    use crate::uri::{PayjoinExtras, UrlExt};
    let id = session_context.id();
    let mut pj = subdir(&session_context.directory, &id);
    pj.set_receiver_pubkey(session_context.s.public_key().clone());
    pj.set_ohttp(session_context.ohttp_keys.clone());
    pj.set_exp(session_context.expiry);
    let extras = PayjoinExtras { endpoint: pj, output_substitution };
    bitcoin_uri::Uri::with_extras(session_context.address.clone(), extras)
}

#[cfg(test)]
pub mod test {
    use std::str::FromStr;

    use bitcoin::FeeRate;
    use once_cell::sync::Lazy;
    use payjoin_test_utils::{
        BoxError, EXAMPLE_URL, KEM, KEY_ID, PARSED_ORIGINAL_PSBT, QUERY_PARAMS, SYMMETRIC,
    };

    use super::*;
    use crate::persist::{NoopSessionPersister, RejectTransient, Rejection};
    use crate::receive::optional_parameters::Params;
    use crate::receive::{v2, ReplyableError};
    use crate::ImplementationError;

    pub(crate) static SHARED_CONTEXT: Lazy<SessionContext> = Lazy::new(|| SessionContext {
        address: Address::from_str("tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4")
            .expect("valid address")
            .assume_checked(),
        directory: EXAMPLE_URL.clone(),
        subdirectory: None,
        ohttp_keys: OhttpKeys(
            ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).expect("valid key config"),
        ),
        expiry: SystemTime::now() + Duration::from_secs(60),
        s: HpkeKeyPair::gen_keypair(),
        e: None,
    });

    pub(crate) static SHARED_CONTEXT_TWO: Lazy<SessionContext> = Lazy::new(|| SessionContext {
        address: Address::from_str("tb1qv7scm7gxs32qg3lnm9kf267kllc63yvdxyh72e")
            .expect("valid address")
            .assume_checked(),
        directory: EXAMPLE_URL.clone(),
        subdirectory: None,
        ohttp_keys: OhttpKeys(
            ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).expect("valid key config"),
        ),
        expiry: SystemTime::now() + Duration::from_secs(60),
        s: HpkeKeyPair::gen_keypair(),
        e: None,
    });

    pub(crate) fn unchecked_proposal_v2_from_test_vector() -> UncheckedProposal {
        let pairs = url::form_urlencoded::parse(QUERY_PARAMS.as_bytes());
        let params = Params::from_query_pairs(pairs, &[Version::Two])
            .expect("Test utils query params should not fail");
        UncheckedProposal {
            v1: v1::UncheckedProposal { psbt: PARSED_ORIGINAL_PSBT.clone(), params },
            context: SHARED_CONTEXT.clone(),
        }
    }

    #[test]
    fn test_unchecked_proposal_transient_error() -> Result<(), BoxError> {
        let unchecked_proposal = unchecked_proposal_v2_from_test_vector();
        let receiver = v2::Receiver { state: unchecked_proposal };

        let unchecked_proposal = receiver.check_broadcast_suitability(Some(FeeRate::MIN), |_| {
            Err(ImplementationError::from(ReplyableError::Implementation("mock error".into())))
        });

        match unchecked_proposal {
            MaybeFatalTransition(Err(Rejection::Transient(RejectTransient(
                ReplyableError::Implementation(error),
            )))) => assert_eq!(
                error.to_string(),
                ReplyableError::Implementation("mock error".into()).to_string()
            ),
            _ => panic!("Expected ReplyableError but got unexpected error or Ok"),
        }

        Ok(())
    }

    #[test]
    fn test_maybe_inputs_seen_transient_error() -> Result<(), BoxError> {
        let unchecked_proposal = unchecked_proposal_v2_from_test_vector();
        let receiver = v2::Receiver { state: unchecked_proposal };

        let maybe_inputs_owned = receiver.assume_interactive_receiver();
        let maybe_inputs_seen = maybe_inputs_owned.0 .1.check_inputs_not_owned(|_| {
            Err(ImplementationError::from(ReplyableError::Implementation("mock error".into())))
        });

        match maybe_inputs_seen {
            MaybeFatalTransition(Err(Rejection::Transient(RejectTransient(
                ReplyableError::Implementation(error),
            )))) => assert_eq!(
                error.to_string(),
                ReplyableError::Implementation("mock error".into()).to_string()
            ),
            _ => panic!("Expected ReplyableError but got unexpected error or Ok"),
        }

        Ok(())
    }

    #[test]
    fn test_outputs_unknown_transient_error() -> Result<(), BoxError> {
        let unchecked_proposal = unchecked_proposal_v2_from_test_vector();
        let receiver = v2::Receiver { state: unchecked_proposal };

        let maybe_inputs_owned = receiver.assume_interactive_receiver();
        let maybe_inputs_seen = maybe_inputs_owned.0 .1.check_inputs_not_owned(|_| Ok(false));
        let outputs_unknown = match maybe_inputs_seen.0 {
            Ok(state) => state.1.check_no_inputs_seen_before(|_| {
                Err(ImplementationError::from(ReplyableError::Implementation("mock error".into())))
            }),
            Err(_) => panic!("Expected Ok, got Err"),
        };

        match outputs_unknown {
            MaybeFatalTransition(Err(Rejection::Transient(RejectTransient(
                ReplyableError::Implementation(error),
            )))) => assert_eq!(
                error.to_string(),
                ReplyableError::Implementation("mock error".into()).to_string()
            ),
            _ => panic!("Expected ReplyableError but got unexpected error or Ok"),
        }

        Ok(())
    }

    #[test]
    fn test_wants_outputs_transient_error() -> Result<(), BoxError> {
        let unchecked_proposal = unchecked_proposal_v2_from_test_vector();
        let receiver = v2::Receiver { state: unchecked_proposal };

        let maybe_inputs_owned = receiver.assume_interactive_receiver();
        let maybe_inputs_seen = maybe_inputs_owned.0 .1.check_inputs_not_owned(|_| Ok(false));
        let outputs_unknown = match maybe_inputs_seen.0 {
            Ok(state) => state.1.check_no_inputs_seen_before(|_| Ok(false)),
            Err(_) => panic!("Expected Ok, got Err"),
        };
        let wants_outputs = match outputs_unknown.0 {
            Ok(state) => state.1.identify_receiver_outputs(|_| {
                Err(ImplementationError::from(ReplyableError::Implementation("mock error".into())))
            }),
            Err(_) => panic!("Expected Ok, got Err"),
        };

        match wants_outputs {
            MaybeFatalTransition(Err(Rejection::Transient(RejectTransient(
                ReplyableError::Implementation(error),
            )))) => assert_eq!(
                error.to_string(),
                ReplyableError::Implementation("mock error".into()).to_string()
            ),
            _ => panic!("Expected ReplyableError but got unexpected error or Ok"),
        }

        Ok(())
    }

    #[test]
    fn test_extract_err_req() -> Result<(), BoxError> {
        let noop_persister = NoopSessionPersister::default();
        let receiver = Receiver { state: unchecked_proposal_v2_from_test_vector() };

        let server_error = || {
            receiver
                .clone()
                .check_broadcast_suitability(None, |_| Err("mock error".into()))
                .save(&noop_persister)
        };

        let expected_json = serde_json::json!({
            "errorCode": "unavailable",
            "message": "Receiver error"
        });

        let error = server_error().expect_err("Server error should be populated with mock error");
        let res = error.api_error().expect("check_broadcast error should propagate to api error");
        let actual_json = JsonReply::from(&res);
        assert_eq!(actual_json.to_json(), expected_json);

        let (_req, _ctx) = extract_err_req(&actual_json, &*EXAMPLE_URL, &SHARED_CONTEXT)?;

        let internal_error: ReplyableError = InternalPayloadError::MissingPayment.into();
        let (_req, _ctx) =
            extract_err_req(&(&internal_error).into(), &*EXAMPLE_URL, &SHARED_CONTEXT)?;
        Ok(())
    }

    #[test]
    fn test_extract_err_req_expiry() -> Result<(), BoxError> {
        let now = SystemTime::now();
        let noop_persister = NoopSessionPersister::default();
        let context = SessionContext { expiry: now, ..SHARED_CONTEXT.clone() };
        let receiver = Receiver {
            state: UncheckedProposal {
                v1: crate::receive::v1::test::unchecked_proposal_from_test_vector(),
                context: context.clone(),
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

        let session = Receiver::create_session(
            SHARED_CONTEXT.address.clone(),
            SHARED_CONTEXT.directory.clone(),
            SHARED_CONTEXT.ohttp_keys.clone(),
            None,
        )
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
    fn test_v2_pj_uri() {
        let uri = Receiver { state: Initialized { context: SHARED_CONTEXT.clone() } }.pj_uri();
        assert_ne!(uri.extras.endpoint, EXAMPLE_URL.clone());
        assert_eq!(uri.extras.output_substitution, OutputSubstitution::Disabled);
    }
}
