//! Receive BIP 77 Payjoin v2
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::psbt::Psbt;
use bitcoin::{Address, FeeRate, OutPoint, Script, TxOut};
pub(crate) use error::InternalSessionError;
pub use error::SessionError;
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use url::Url;

use super::error::{Error, InputContributionError};
use super::{
    v1, InternalPayloadError, JsonReply, OutputSubstitutionError, ReplyableError, SelectionError,
};
use crate::hpke::{decrypt_message_a, encrypt_message_b, HpkeKeyPair, HpkePublicKey};
use crate::ohttp::{ohttp_decapsulate, ohttp_encapsulate, OhttpEncapsulationError, OhttpKeys};
use crate::output_substitution::OutputSubstitution;
use crate::persist::{
    AcceptCompleted, AcceptNextState, MaybeBadInitInputsTransition, MaybeFatalRejection,
    MaybeFatalTransition, MaybeFatalTransitionWithNoResults, MaybeSuccessTransition,
    MaybeTransientTransition, NextStateTransition, PersistedSession, RejectBadInitInputs,
    RejectFatal, RejectTransient,
};
use crate::receive::{parse_payload, InputPair};
use crate::uri::ShortId;
use crate::{ImplementationError, IntoUrl, IntoUrlError, PjUri, Request, Version};

mod error;

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
    pub fn id(&self) -> ShortId { id(&self.s) }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
/// represents a piece of information that the reciever has learned about the session
/// Each event can be used to transition the receiver state machine to a new state
pub enum ReceiverSessionEvent {
    /// Receiver was created
    Created(SessionContext),
    /// Receiver read a proposal from a directory
    UncheckedProposal(v1::UncheckedProposal),
    MaybeInputsOwned(v1::MaybeInputsOwned),
    MaybeInputsSeen(v1::MaybeInputsSeen),
    OutputsUnknown(v1::OutputsUnknown),
    WantsOutputs(v1::WantsOutputs),
    WantsInputs(v1::WantsInputs),
    ProvisionalProposal(v1::ProvisionalProposal),
    PayjoinProposal(v1::PayjoinProposal),
    /// Fallback broadcasted
    FallbackBroadcasted(bitcoin::Txid),
    /// Original tx cannot be broadcasted
    OriginalTxCannotBeBroadcasted(bitcoin::Txid),
    /// Session is invalid. This is a irrecoverable error. Fallback tx should be broadcasted.
    /// TODO this should be any error type that is impl std::error and works well with serde, or as a fallback can be formatted as a string
    /// Reason being in some cases we still want to preserve the error b/c the cause the session to fail but these are terminal states we dont need them to be structured or well typed
    /// b/c its a terminal state and there is nothing to replay. So serialization will be lossy and that is fine.
    SessionInvalid(String),
}

#[derive(Debug)]
pub enum ReceiverReplayError {
    /// Session expired
    SessionExpired(SystemTime),
    /// Invalid combination of state and event
    InvalidStateAndEvent,
}

#[derive(Debug, Clone)]
pub enum ReceiverState {
    Uninitialized(Receiver<UninitializedReceiver>),
    WithContext(Receiver<ReceiverWithContext>),
    UncheckedProposal(Receiver<UncheckedProposal>),
    MaybeInputsOwned(Receiver<MaybeInputsOwned>),
    MaybeInputsSeen(Receiver<MaybeInputsSeen>),
    OutputsUnknown(Receiver<OutputsUnknown>),
    WantsOutputs(Receiver<WantsOutputs>),
    WantsInputs(Receiver<WantsInputs>),
    ProvisionalProposal(Receiver<ProvisionalProposal>),
    PayjoinProposal(Receiver<PayjoinProposal>),
    TerminalState,
}

impl ReceiverState {
    fn process_event(
        self,
        event: ReceiverSessionEvent,
    ) -> Result<ReceiverState, ReceiverReplayError> {
        match (self, event) {
            (ReceiverState::Uninitialized(_), ReceiverSessionEvent::Created(context)) =>
                Ok(ReceiverState::WithContext(Receiver { state: ReceiverWithContext { context } })),

            (
                ReceiverState::WithContext(state),
                ReceiverSessionEvent::UncheckedProposal(proposal),
            ) => Ok(state.apply_unchecked_from_payload(proposal)?),

            (
                ReceiverState::UncheckedProposal(state),
                ReceiverSessionEvent::MaybeInputsOwned(inputs),
            ) => Ok(state.apply_maybe_inputs_owned(inputs)),

            (
                ReceiverState::MaybeInputsOwned(state),
                ReceiverSessionEvent::MaybeInputsSeen(maybe_inputs_seen),
            ) => Ok(state.apply_maybe_inputs_seen(maybe_inputs_seen)),

            (
                ReceiverState::MaybeInputsSeen(state),
                ReceiverSessionEvent::OutputsUnknown(outputs_unknown),
            ) => Ok(state.apply_outputs_unknown(outputs_unknown)),

            (
                ReceiverState::OutputsUnknown(state),
                ReceiverSessionEvent::WantsOutputs(wants_outputs),
            ) => Ok(state.apply_wants_outputs(wants_outputs)),

            (
                ReceiverState::WantsOutputs(state),
                ReceiverSessionEvent::WantsInputs(wants_inputs),
            ) => Ok(state.apply_wants_inputs(wants_inputs)),

            (
                ReceiverState::WantsInputs(state),
                ReceiverSessionEvent::ProvisionalProposal(provisional_proposal),
            ) => Ok(state.apply_provisional_proposal(provisional_proposal)),

            (
                ReceiverState::ProvisionalProposal(state),
                ReceiverSessionEvent::PayjoinProposal(payjoin_proposal),
            ) => Ok(state.apply_payjoin_proposal(payjoin_proposal)),
            (_, ReceiverSessionEvent::SessionInvalid(_)) => Ok(ReceiverState::TerminalState),
            // TODO: Handle invalid transitions with a catch-all that provides better error info
            (_current_state, _event) => Err(ReceiverReplayError::InvalidStateAndEvent),
        }
    }
}

pub fn replay_receiver_event_log<P>(
    persister: P,
) -> Result<(ReceiverState, SessionHistory), ReceiverReplayError>
where
    P: PersistedSession + Clone,
    P::SessionEvent: From<ReceiverSessionEvent>,
    ReceiverSessionEvent: From<P::SessionEvent>,
{
    // TODO: fix this
    let logs = persister.load().unwrap();
    let mut receiver = ReceiverState::Uninitialized(Receiver { state: UninitializedReceiver {} });
    let mut history = SessionHistory::new(Vec::new());

    for log in logs {
        history.events.push(log.clone().into());
        // TODO: remove clone
        match receiver.clone().process_event(log.into()) {
            Ok(next_receiver) => {
                receiver = next_receiver;
            }
            Err(_e) => {
                // All error cases are terminal. Close the session in its current state
                persister.close().unwrap();
                break;
            }
        }
    }

    Ok((receiver, history))
}

#[derive(Clone)]
pub struct SessionHistory {
    events: Vec<ReceiverSessionEvent>,
}

impl SessionHistory {
    fn new(events: Vec<ReceiverSessionEvent>) -> Self { Self { events } }

    pub fn pj_uri<'a>(&self) -> Option<PjUri<'a>> {
        self.events.iter().find_map(|event| match event {
            ReceiverSessionEvent::Created(session_context) => {
                // TODO this code was copied from ReceiverWithContext::pj_uri. Should be deduped
                use crate::uri::{PayjoinExtras, UrlExt};
                let id = id(&session_context.s);
                let mut pj = subdir(&session_context.directory, &id).clone();
                pj.set_receiver_pubkey(session_context.s.public_key().clone());
                pj.set_ohttp(session_context.ohttp_keys.clone());
                pj.set_exp(session_context.expiry);
                let extras = PayjoinExtras {
                    endpoint: pj,
                    output_substitution: OutputSubstitution::Disabled,
                };
                Some(bitcoin_uri::Uri::with_extras(session_context.address.clone(), extras))
            }
            _ => None,
        })
    }

    pub fn payment_amount(&self) -> Option<bitcoin::Amount> { self.pj_uri().map(|uri| uri.amount)? }

    pub fn payment_address(&self) -> Option<bitcoin::Address<bitcoin::address::NetworkChecked>> {
        self.pj_uri().map(|uri| uri.address)
    }

    pub fn proposal_txid(&self) -> Option<bitcoin::Txid> {
        self.events.iter().find_map(|event| match event {
            ReceiverSessionEvent::ProvisionalProposal(proposal) =>
                Some(proposal.payjoin_psbt.unsigned_tx.compute_txid()),
            _ => None,
        })
    }

    pub fn fallback_txid(&self) -> Option<bitcoin::Txid> {
        self.events.iter().find_map(|event| match event {
            ReceiverSessionEvent::UncheckedProposal(proposal) =>
                Some(proposal.psbt.unsigned_tx.compute_txid()),
            _ => None,
        })
    }
}
#[derive(Debug, Clone)]
pub struct Receiver<State> {
    state: State,
}

#[derive(Debug, Clone)]
/// The receiver is not initialized yet, no session context is available yet
pub struct UninitializedReceiver {}

impl Receiver<UninitializedReceiver> {
    pub fn create_session(
        address: Address,
        directory: impl IntoUrl,
        ohttp_keys: OhttpKeys,
        expire_after: Option<Duration>,
    ) -> MaybeBadInitInputsTransition<
        ReceiverSessionEvent,
        Receiver<ReceiverWithContext>,
        IntoUrlError,
    > {
        let directory = match directory.into_url() {
            Ok(url) => url,
            Err(e) => return MaybeBadInitInputsTransition(Err(RejectBadInitInputs(e))),
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

        let event = ReceiverSessionEvent::Created(session_context.clone());
        MaybeBadInitInputsTransition(Ok(AcceptNextState(
            event,
            Receiver { state: ReceiverWithContext { context: session_context } },
        )))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiverWithContext {
    context: SessionContext,
}

impl Receiver<ReceiverWithContext> {
    /// Extract an OHTTP Encapsulated HTTP GET request for the Original PSBT
    pub fn extract_req(
        &mut self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), Error> {
        if SystemTime::now() > self.state.context.expiry {
            // Session is expired, close the session
            // TODO: remove unwrap
            // self.persister.close().unwrap();
            return Err(InternalSessionError::Expired(self.state.context.expiry).into());
        }
        let (body, ohttp_ctx) =
            self.fallback_req_body().map_err(InternalSessionError::OhttpEncapsulation)?;
        let req = Request::new_v2(&self.state.context.full_relay_url(ohttp_relay)?, &body);
        Ok((req, ohttp_ctx))
    }

    pub fn process_res(
        self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> MaybeFatalTransitionWithNoResults<
        ReceiverSessionEvent,
        Receiver<UncheckedProposal>,
        Receiver<ReceiverWithContext>,
        Error,
    > {
        let session_context = self.state.context.clone();
        let current_state = self.clone();
        let (proposal, e) = match self.inner_process_res(body, context) {
            Ok((proposal, reply_key)) => (proposal, reply_key),
            Err(e) => {
                // Dir and OHTTP related error are transient
                // Malformities or invalid responses are considered fatal
                // TODO: could use granular session event for specific error types
                let err = match e {
                    Error::ReplyToSender(ref reply_error) => match reply_error {
                        ReplyableError::Implementation(_) =>
                            MaybeFatalRejection::Transient(RejectTransient(e)),
                        _ => MaybeFatalRejection::Fatal(RejectFatal(
                            ReceiverSessionEvent::SessionInvalid(e.to_string()),
                            e,
                        )),
                    },
                    _ => MaybeFatalRejection::Fatal(RejectFatal(
                        ReceiverSessionEvent::SessionInvalid(e.to_string()),
                        e,
                    )),
                };
                return MaybeFatalTransitionWithNoResults::Err(err);
            }
        };

        if let Some(proposal) = proposal {
            MaybeFatalTransitionWithNoResults::success(
                ReceiverSessionEvent::UncheckedProposal(proposal.clone()),
                Receiver {
                    state: UncheckedProposal {
                        v1: proposal,
                        context: SessionContext { e, ..session_context },
                    },
                },
            )
        } else {
            MaybeFatalTransitionWithNoResults::no_results(current_state)
        }
    }

    /// The response can either be an UncheckedProposal or an ACCEPTED message
    /// indicating no UncheckedProposal is available yet.
    fn inner_process_res(
        self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> Result<(Option<v1::UncheckedProposal>, Option<HpkePublicKey>), Error> {
        let response_array: &[u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES] =
            body.try_into()
                .map_err(|_| InternalSessionError::UnexpectedResponseSize(body.len()))?;
        log::trace!("decapsulating directory response");
        let response = ohttp_decapsulate(context, response_array)
            .map_err(InternalSessionError::OhttpEncapsulation)?;
        if response.body().is_empty() {
            log::debug!("response is empty");
            return Ok((None, None));
        }
        match String::from_utf8(response.body().to_vec()) {
            // V1 response bodies are utf8 plaintext
            Ok(response) => Ok((Some(self.extract_proposal_from_v1(response)?), None)),
            // V2 response bodies are encrypted binary
            Err(_) => {
                let (proposal, reply_key) =
                    self.extract_proposal_from_v2(response.body().to_vec())?;
                Ok((Some(proposal), Some(reply_key)))
            }
        }
    }

    fn fallback_req_body(
        &mut self,
    ) -> Result<
        ([u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES], ohttp::ClientResponse),
        OhttpEncapsulationError,
    > {
        let fallback_target = subdir(&self.state.context.directory, &self.id());
        ohttp_encapsulate(&mut self.state.context.ohttp_keys, "GET", fallback_target.as_str(), None)
    }

    fn extract_proposal_from_v1(
        self,
        response: String,
    ) -> Result<v1::UncheckedProposal, ReplyableError> {
        self.unchecked_from_payload(response)
    }

    fn extract_proposal_from_v2(
        self,
        response: Vec<u8>,
    ) -> Result<(v1::UncheckedProposal, HpkePublicKey), Error> {
        let (payload_bytes, e) =
            decrypt_message_a(&response, self.state.context.s.secret_key().clone())?;
        let payload = String::from_utf8(payload_bytes)
            .map_err(|e| Error::ReplyToSender(InternalPayloadError::Utf8(e).into()))?;
        let proposal = self.unchecked_from_payload(payload).map_err(Error::ReplyToSender)?;
        Ok((proposal, e))
    }

    fn unchecked_from_payload(
        self,
        payload: String,
    ) -> Result<v1::UncheckedProposal, ReplyableError> {
        let (base64, padded_query) = payload.split_once('\n').unwrap_or_default();
        let query = padded_query.trim_matches('\0');
        log::trace!("Received query: {query}, base64: {base64}"); // my guess is no \n so default is wrong
        let (psbt, mut params) = parse_payload(base64.to_string(), query, SUPPORTED_VERSIONS)
            .map_err(ReplyableError::Payload)?;

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

        let proposal = v1::UncheckedProposal { psbt, params };

        Ok(proposal)
    }

    /// Build a V2 Payjoin URI from the receiver's context
    pub fn pj_uri<'a>(&self) -> crate::PjUri<'a> {
        use crate::uri::{PayjoinExtras, UrlExt};
        let mut pj = subdir(&self.state.context.directory, &self.id()).clone();
        pj.set_receiver_pubkey(self.state.context.s.public_key().clone());
        pj.set_ohttp(self.state.context.ohttp_keys.clone());
        pj.set_exp(self.state.context.expiry);
        let extras =
            PayjoinExtras { endpoint: pj, output_substitution: OutputSubstitution::Disabled };
        bitcoin_uri::Uri::with_extras(self.state.context.address.clone(), extras)
    }

    /// The per-session identifier
    pub fn id(&self) -> ShortId { id(&self.state.context.s) }

    pub fn apply_unchecked_from_payload(
        self,
        event: v1::UncheckedProposal,
    ) -> Result<ReceiverState, ReceiverReplayError> {
        if self.state.context.expiry < SystemTime::now() {
            // Session is expired, close the session
            return Err(ReceiverReplayError::SessionExpired(self.state.context.expiry));
        }

        let new_state = Receiver {
            state: UncheckedProposal { v1: event, context: self.state.context.clone() },
        };

        Ok(ReceiverState::UncheckedProposal(new_state))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UncheckedProposal {
    pub(crate) v1: v1::UncheckedProposal,
    pub(crate) context: SessionContext,
}

impl Receiver<UncheckedProposal> {
    /// Call after checking that the Original PSBT can be broadcast.
    ///
    /// Receiver MUST check that the Original PSBT from the sender
    /// can be broadcast, i.e. `testmempoolaccept` bitcoind rpc returns { "allowed": true,.. }
    /// for `extract_tx_to_schedule_broadcast()` before calling this method.
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
        can_broadcast: impl Fn(&bitcoin::Transaction) -> Result<bool, ImplementationError>,
    ) -> MaybeFatalTransition<ReceiverSessionEvent, Receiver<MaybeInputsOwned>, Error> {
        let v1 =
            match self.state.v1.clone().check_broadcast_suitability(min_fee_rate, can_broadcast) {
                Ok(v1) => v1,
                Err(e) => {
                    match e {
                        ReplyableError::Implementation(_) => {
                            return MaybeFatalTransition::transient(Error::ReplyToSender(e));
                        }
                        // Payload or spec related error as treated as fatal
                        _ => {
                            return MaybeFatalTransition::fatal(
                                ReceiverSessionEvent::SessionInvalid(e.to_string()),
                                Error::ReplyToSender(e),
                            );
                        }
                    }
                }
            };
        MaybeFatalTransition::Ok(AcceptNextState(
            ReceiverSessionEvent::MaybeInputsOwned(v1.clone()),
            Receiver { state: MaybeInputsOwned { v1, context: self.state.context.clone() } },
        ))
    }

    /// Note to self: this is the public entry point for replayability

    /// The Sender's Original PSBT
    pub fn extract_tx_to_schedule_broadcast(&self) -> bitcoin::Transaction {
        self.state.v1.extract_tx_to_schedule_broadcast()
    }

    /// Call this method if the only way to initiate a Payjoin with this receiver
    /// requires manual intervention, as in most consumer wallets.
    ///
    /// So-called "non-interactive" receivers, like payment processors, that allow arbitrary requests are otherwise vulnerable to probing attacks.
    /// Those receivers call `extract_tx_to_check_broadcast()` and `attest_tested_and_scheduled_broadcast()` after making those checks downstream.
    pub fn assume_interactive_receiver(
        self,
    ) -> AcceptNextState<ReceiverSessionEvent, Receiver<MaybeInputsOwned>> {
        let inner = self.state.v1.assume_interactive_receiver();
        AcceptNextState(
            ReceiverSessionEvent::MaybeInputsOwned(inner.clone()),
            Receiver { state: MaybeInputsOwned { v1: inner, context: self.state.context } },
        )
    }

    /// Extract an OHTTP Encapsulated HTTP POST request to return
    /// a Receiver Error Response
    pub fn extract_err_req(
        &mut self,
        err: &JsonReply,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), SessionError> {
        let subdir = subdir(&self.state.context.directory, &id(&self.state.context.s));
        let (body, ohttp_ctx) = ohttp_encapsulate(
            &mut self.state.context.ohttp_keys,
            "POST",
            subdir.as_str(),
            Some(err.to_json().to_string().as_bytes()),
        )
        .map_err(InternalSessionError::OhttpEncapsulation)?;
        let req = Request::new_v2(&self.state.context.full_relay_url(ohttp_relay)?, &body);
        Ok((req, ohttp_ctx))
    }

    /// Process an OHTTP Encapsulated HTTP POST Error response
    /// to ensure it has been posted properly
    pub fn process_err_res(
        &mut self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> Result<(), SessionError> {
        let response_array: &[u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES] =
            body.try_into()
                .map_err(|_| InternalSessionError::UnexpectedResponseSize(body.len()))?;
        let response = ohttp_decapsulate(context, response_array)
            .map_err(InternalSessionError::OhttpEncapsulation)?;

        match response.status() {
            http::StatusCode::OK => Ok(()),
            _ => Err(InternalSessionError::UnexpectedStatusCode(response.status()).into()),
        }
    }

    pub fn apply_maybe_inputs_owned(self, v1: v1::MaybeInputsOwned) -> ReceiverState {
        let new_state =
            Receiver { state: MaybeInputsOwned { v1, context: self.state.context.clone() } };
        ReceiverState::MaybeInputsOwned(new_state)
    }

    pub fn inner(&self) -> UncheckedProposal { self.state.clone() }

    /// The per-session identifier
    pub fn id(&self) -> ShortId { id(&self.state.context.s) }
}

#[derive(Debug, Clone)]
pub struct MaybeInputsOwned {
    v1: v1::MaybeInputsOwned,
    context: SessionContext,
}

impl Receiver<MaybeInputsOwned> {
    /// Check that the Original PSBT has no receiver-owned inputs.
    /// Return original-psbt-rejected error or otherwise refuse to sign undesirable inputs.
    ///
    /// An attacker could try to spend receiver's own inputs. This check prevents that.
    pub fn check_inputs_not_owned(
        self,
        is_owned: impl Fn(&Script) -> Result<bool, ImplementationError>,
    ) -> MaybeFatalTransition<ReceiverSessionEvent, Receiver<MaybeInputsSeen>, ReplyableError> {
        let inner = match self.state.v1.clone().check_inputs_not_owned(is_owned) {
            Ok(inner) => inner,
            Err(e) => match e {
                ReplyableError::Implementation(_) => {
                    return MaybeFatalTransition::transient(e);
                }
                _ => {
                    return MaybeFatalTransition::fatal(
                        ReceiverSessionEvent::SessionInvalid(e.to_string()),
                        e,
                    );
                }
            },
        };
        MaybeFatalTransition::success(
            ReceiverSessionEvent::MaybeInputsSeen(inner.clone()),
            Receiver { state: MaybeInputsSeen { v1: inner, context: self.state.context.clone() } },
        )
    }

    pub fn apply_maybe_inputs_seen(self, v1: v1::MaybeInputsSeen) -> ReceiverState {
        let new_state =
            Receiver { state: MaybeInputsSeen { v1, context: self.state.context.clone() } };
        ReceiverState::MaybeInputsSeen(new_state)
    }
}

/// Typestate to validate that the Original PSBT has no inputs that have been seen before.
///
/// Call [`Self::check_no_inputs_seen_before`] to proceed.
#[derive(Debug, Clone)]
pub struct MaybeInputsSeen {
    v1: v1::MaybeInputsSeen,
    context: SessionContext,
}

impl Receiver<MaybeInputsSeen> {
    /// Make sure that the original transaction inputs have never been seen before.
    /// This prevents probing attacks. This prevents reentrant Payjoin, where a sender
    /// proposes a Payjoin PSBT as a new Original PSBT for a new Payjoin.
    pub fn check_no_inputs_seen_before(
        self,
        is_known: impl Fn(&OutPoint) -> Result<bool, ImplementationError>,
    ) -> MaybeFatalTransition<ReceiverSessionEvent, Receiver<OutputsUnknown>, ReplyableError> {
        let inner = match self.state.v1.clone().check_no_inputs_seen_before(is_known) {
            Ok(inner) => inner,
            Err(e) => match e {
                ReplyableError::Implementation(_) => {
                    return MaybeFatalTransition::transient(e);
                }
                _ => {
                    return MaybeFatalTransition::fatal(
                        ReceiverSessionEvent::SessionInvalid(e.to_string()),
                        e,
                    );
                }
            },
        };
        MaybeFatalTransition::success(
            ReceiverSessionEvent::OutputsUnknown(inner.clone()),
            Receiver { state: OutputsUnknown { v1: inner, context: self.state.context.clone() } },
        )
    }

    pub fn apply_outputs_unknown(self, v1: v1::OutputsUnknown) -> ReceiverState {
        let new_state =
            Receiver { state: OutputsUnknown { v1, context: self.state.context.clone() } };
        ReceiverState::OutputsUnknown(new_state)
    }
}

/// The receiver has not yet identified which outputs belong to the receiver.
///
/// Only accept PSBTs that send us money.
/// Identify those outputs with [`Self::identify_receiver_outputs`] to proceed.
#[derive(Debug, Clone)]
pub struct OutputsUnknown {
    v1: v1::OutputsUnknown,
    context: SessionContext,
}

impl Receiver<OutputsUnknown> {
    /// Find which outputs belong to the receiver
    pub fn identify_receiver_outputs(
        self,
        is_receiver_output: impl Fn(&Script) -> Result<bool, ImplementationError>,
    ) -> MaybeFatalTransition<ReceiverSessionEvent, Receiver<WantsOutputs>, ReplyableError> {
        let inner = match self.state.v1.clone().identify_receiver_outputs(is_receiver_output) {
            Ok(inner) => inner,
            Err(e) => match e {
                ReplyableError::Implementation(_) => {
                    return MaybeFatalTransition::transient(e);
                }
                _ => {
                    return MaybeFatalTransition::fatal(
                        ReceiverSessionEvent::SessionInvalid(e.to_string()),
                        e,
                    );
                }
            },
        };
        MaybeFatalTransition::success(
            ReceiverSessionEvent::WantsOutputs(inner.clone()),
            Receiver { state: WantsOutputs { v1: inner, context: self.state.context.clone() } },
        )
    }

    pub fn apply_wants_outputs(self, v1: v1::WantsOutputs) -> ReceiverState {
        let new_state =
            Receiver { state: WantsOutputs { v1, context: self.state.context.clone() } };
        ReceiverState::WantsOutputs(new_state)
    }
}
/// A checked proposal that the receiver may substitute or add outputs to
///
/// Call [`Self::commit_outputs`] to proceed.
#[derive(Debug, Clone)]
pub struct WantsOutputs {
    v1: v1::WantsOutputs,
    context: SessionContext,
}

impl Receiver<WantsOutputs> {
    /// Whether the receiver is allowed to substitute original outputs or not.
    pub fn output_substitution(&self) -> OutputSubstitution { self.state.v1.output_substitution() }

    /// Substitute the receiver output script with the provided script.
    pub fn substitute_receiver_script(
        self,
        output_script: &Script,
    ) -> Result<Self, OutputSubstitutionError> {
        let inner = self.state.v1.substitute_receiver_script(output_script)?;
        Ok(Receiver { state: WantsOutputs { v1: inner, context: self.state.context.clone() } })
    }

    /// Replace **all** receiver outputs with one or more provided outputs.
    /// The drain script specifies which address to *drain* coins to. An output corresponding to
    /// that address must be included in `replacement_outputs`. The value of that output may be
    /// increased or decreased depending on the receiver's input contributions and whether the
    /// receiver needs to pay for additional miner fees (e.g. in the case of adding many outputs).
    pub fn replace_receiver_outputs(
        self,
        replacement_outputs: impl IntoIterator<Item = TxOut>,
        drain_script: &Script,
    ) -> Result<Self, OutputSubstitutionError> {
        let inner = self.state.v1.replace_receiver_outputs(replacement_outputs, drain_script)?;
        Ok(Receiver { state: WantsOutputs { v1: inner, context: self.state.context.clone() } })
    }

    /// Proceed to the input contribution step.
    /// Outputs cannot be modified after this function is called.
    pub fn commit_outputs(
        self,
    ) -> NextStateTransition<ReceiverSessionEvent, Receiver<WantsInputs>> {
        let inner = self.state.v1.clone().commit_outputs();
        NextStateTransition(AcceptNextState(
            ReceiverSessionEvent::WantsInputs(inner.clone()),
            Receiver { state: WantsInputs { v1: inner, context: self.state.context.clone() } },
        ))
    }

    pub fn apply_wants_inputs(self, v1: v1::WantsInputs) -> ReceiverState {
        let new_state = Receiver { state: WantsInputs { v1, context: self.state.context.clone() } };
        ReceiverState::WantsInputs(new_state)
    }
}

/// A checked proposal that the receiver may contribute inputs to to make a payjoin
///
/// Call [`Self::commit_inputs`] to proceed.
#[derive(Debug, Clone)]
pub struct WantsInputs {
    v1: v1::WantsInputs,
    context: SessionContext,
}

impl Receiver<WantsInputs> {
    /// Select receiver input such that the payjoin avoids surveillance.
    /// Return the input chosen that has been applied to the Proposal.
    ///
    /// Proper coin selection allows payjoin to resemble ordinary transactions.
    /// To ensure the resemblance, a number of heuristics must be avoided.
    ///
    /// UIH "Unnecessary input heuristic" is one class of them to avoid. We define
    /// UIH1 and UIH2 according to the BlockSci practice
    /// BlockSci UIH1 and UIH2:
    /// if min(in) > min(out) then UIH1 else UIH2
    /// <https://eprint.iacr.org/2022/589.pdf>
    pub fn try_preserving_privacy(
        &self,
        candidate_inputs: impl IntoIterator<Item = InputPair>,
    ) -> Result<InputPair, SelectionError> {
        self.state.v1.try_preserving_privacy(candidate_inputs)
    }

    /// Add the provided list of inputs to the transaction.
    /// Any excess input amount is added to the change_vout output indicated previously.
    pub fn contribute_inputs(
        self,
        inputs: impl IntoIterator<Item = InputPair>,
    ) -> Result<Self, InputContributionError> {
        let inner = self.state.v1.clone().contribute_inputs(inputs)?;
        Ok(Receiver { state: WantsInputs { v1: inner, context: self.state.context.clone() } })
    }

    /// Proceed to the proposal finalization step.
    /// Inputs cannot be modified after this function is called.
    pub fn commit_inputs(
        self,
    ) -> NextStateTransition<ReceiverSessionEvent, Receiver<ProvisionalProposal>> {
        let inner = self.state.v1.clone().commit_inputs();
        NextStateTransition(AcceptNextState(
            ReceiverSessionEvent::ProvisionalProposal(inner.clone()),
            Receiver {
                state: ProvisionalProposal { v1: inner, context: self.state.context.clone() },
            },
        ))
    }

    pub fn apply_provisional_proposal(self, v1: v1::ProvisionalProposal) -> ReceiverState {
        let new_state =
            Receiver { state: ProvisionalProposal { v1, context: self.state.context.clone() } };
        ReceiverState::ProvisionalProposal(new_state)
    }
}

/// A checked proposal that the receiver may finalize
///
/// Call [`Self::finalize_proposal`] to proceed.
#[derive(Debug, Clone)]
pub struct ProvisionalProposal {
    v1: v1::ProvisionalProposal,
    context: SessionContext,
}

impl Receiver<ProvisionalProposal> {
    pub fn finalize_proposal(
        self,
        wallet_process_psbt: impl Fn(&Psbt) -> Result<Psbt, ImplementationError>,
        min_fee_rate: Option<FeeRate>,
        max_effective_fee_rate: Option<FeeRate>,
    ) -> MaybeTransientTransition<ReceiverSessionEvent, Receiver<PayjoinProposal>, ReplyableError>
    {
        let inner = match self.state.v1.clone().finalize_proposal(
            wallet_process_psbt,
            min_fee_rate,
            max_effective_fee_rate,
        ) {
            Ok(inner) => inner,
            Err(e) => {
                // v1::finalize_proposal returns a ReplyableError but the only error that can be returned is ImplementationError from the closure
                // And that is a transient error
                return Err(RejectTransient(e)).into();
            }
        };
        Ok(AcceptNextState(
            ReceiverSessionEvent::PayjoinProposal(inner.clone()),
            Receiver { state: PayjoinProposal { v1: inner, context: self.state.context.clone() } },
        ))
        .into()
    }

    pub fn apply_payjoin_proposal(self, v1: v1::PayjoinProposal) -> ReceiverState {
        let new_state =
            Receiver { state: PayjoinProposal { v1, context: self.state.context.clone() } };
        ReceiverState::PayjoinProposal(new_state)
    }
}
/// A finalized payjoin proposal, complete with fees and receiver signatures, that the sender
/// should find acceptable.
#[derive(Debug, Clone)]
pub struct PayjoinProposal {
    v1: v1::PayjoinProposal,
    context: SessionContext,
}

impl PayjoinProposal {
    #[cfg(feature = "_multiparty")]
    pub(crate) fn new(v1: v1::PayjoinProposal, context: SessionContext) -> Self {
        Self { v1, context }
    }
}

impl Receiver<PayjoinProposal> {
    #[cfg(feature = "_multiparty")]
    pub fn new(proposal: PayjoinProposal) -> Self { Self { state: proposal } }

    /// The UTXOs that would be spent by this Payjoin transaction
    pub fn utxos_to_be_locked(&self) -> impl '_ + Iterator<Item = &bitcoin::OutPoint> {
        self.state.v1.utxos_to_be_locked()
    }

    /// The Payjoin Proposal PSBT
    pub fn psbt(&self) -> &Psbt { self.state.v1.psbt() }

    /// Extract an OHTTP Encapsulated HTTP POST request for the Proposal PSBT
    pub fn extract_req(
        &mut self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), Error> {
        let target_resource: Url;
        let body: Vec<u8>;
        let method: &str;

        if let Some(e) = &self.state.context.e {
            // Prepare v2 payload
            let payjoin_bytes = self.state.v1.psbt().serialize();
            let sender_subdir = subdir_path_from_pubkey(e);
            target_resource = self
                .state
                .context
                .directory
                .join(&sender_subdir.to_string())
                .map_err(|e| ReplyableError::Implementation(e.into()))?;
            body = encrypt_message_b(payjoin_bytes, &self.state.context.s, e)?;
            method = "POST";
        } else {
            // Prepare v2 wrapped and backwards-compatible v1 payload
            body = self.state.v1.psbt().to_string().as_bytes().to_vec();
            let receiver_subdir = subdir_path_from_pubkey(self.state.context.s.public_key());
            target_resource = self
                .state
                .context
                .directory
                .join(&receiver_subdir.to_string())
                .map_err(|e| ReplyableError::Implementation(e.into()))?;
            method = "PUT";
        }
        log::debug!("Payjoin PSBT target: {}", target_resource.as_str());
        let (body, ctx) = ohttp_encapsulate(
            &mut self.state.context.ohttp_keys,
            method,
            target_resource.as_str(),
            Some(&body),
        )?;

        let req = Request::new_v2(&self.state.context.full_relay_url(ohttp_relay)?, &body);
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
        self,
        res: &[u8],
        ohttp_context: ohttp::ClientResponse,
    ) -> MaybeSuccessTransition<Error> {
        let response_array: &[u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES] =
            match res.try_into() {
                Ok(response_array) => response_array,
                Err(_) =>
                    return Err(RejectTransient(Error::V2(
                        InternalSessionError::UnexpectedResponseSize(res.len()).into(),
                    )))
                    .into(),
            };
        let res = match ohttp_decapsulate(ohttp_context, response_array) {
            Ok(res) => res,
            Err(e) =>
                return Err(RejectTransient(Error::V2(
                    InternalSessionError::OhttpEncapsulation(e).into(),
                )))
                .into(),
        };
        if res.status().is_success() {
            Ok(AcceptCompleted()).into()
        } else {
            // Directory error is transient
            return Err(RejectTransient(
                InternalSessionError::UnexpectedStatusCode(res.status()).into(),
            ))
            .into();
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

/// The per-session identifier
fn id(s: &HpkeKeyPair) -> ShortId {
    sha256::Hash::hash(&s.public_key().to_compressed_bytes()).into()
}

#[cfg(test)]
pub mod test {
    use std::str::FromStr;

    use once_cell::sync::Lazy;
    use payjoin_test_utils::{BoxError, EXAMPLE_URL, KEM, KEY_ID, SYMMETRIC};

    use super::*;
    use crate::persist::Value;

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

    #[test]
    fn extract_err_req() -> Result<(), BoxError> {
        let mut proposal = UncheckedProposal {
            v1: crate::receive::v1::test::unchecked_proposal_from_test_vector(),
            context: SHARED_CONTEXT.clone(),
        };

        let server_error = || {
            proposal
                .clone()
                .check_broadcast_suitability(None, |_| Err("mock error".into()))
                .expect_err("expected broadcast suitability check to fail")
        };

        let expected_json = serde_json::json!({
            "errorCode": "unavailable",
            "message": "Receiver error"
        });

        let actual_json = JsonReply::from(server_error()).to_json().clone();
        assert_eq!(actual_json, expected_json);

        let (_req, _ctx) =
            proposal.clone().extract_err_req(&server_error().into(), &*EXAMPLE_URL)?;

        let internal_error: ReplyableError = InternalPayloadError::MissingPayment.into();
        let (_req, _ctx) = proposal.extract_err_req(&internal_error.into(), &*EXAMPLE_URL)?;
        Ok(())
    }

    #[test]
    fn receiver_ser_de_roundtrip() -> Result<(), serde_json::Error> {
        let session = Receiver { context: SHARED_CONTEXT.clone() };
        let serialized = serde_json::to_string(&session)?;
        let deserialized: Receiver = serde_json::from_str(&serialized)?;
        assert_eq!(session, deserialized);
        Ok(())
    }
    // #[test]
    // fn extract_err_req() -> Result<(), BoxError> {
    //     let mut proposal = UncheckedProposal {
    //         v1: crate::receive::v1::test::unchecked_proposal_from_test_vector(),
    //         context: SHARED_CONTEXT.clone(),
    //     };

    #[test]
    fn test_v2_pj_uri() {
        let uri = Receiver { context: SHARED_CONTEXT.clone() }.pj_uri();
        assert_ne!(uri.extras.endpoint, EXAMPLE_URL.clone());
        assert_eq!(uri.extras.output_substitution, OutputSubstitution::Enabled);
    }
}
