//! Receive BIP 77 Payjoin v2
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::psbt::Psbt;
use bitcoin::{Address, FeeRate, OutPoint, Script, TxOut};
pub(crate) use error::InternalSessionError;
pub use error::SessionError;
pub use persist::ReceiverToken;
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
use crate::persist::PersistedSession;
use crate::receive::{parse_payload, InputPair};
use crate::uri::ShortId;
use crate::{ImplementationError, IntoUrl, IntoUrlError, PjUri, Request, Version};

mod error;
mod persist;

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
    /// Session is invalid. This is a irrecoverable error. Fallback tx should be broadcasted.
    /// TODO this should be any error type that is impl std::error and works well with serde, or as a fallback can be formatted as a string
    /// Reason being in some cases we still want to preserve the error b/c the cause the session to fail but these are terminal states we dont need them to be structured or well typed
    /// b/c its a terminal state and there is nothing to replay. So serialization will be lossy and that is fine.
    SessionInvalid(String),
}

#[derive(Debug)]
pub enum ReceiverReplayError {
    /// The session is invalid
    SessionInvalid(String),
    /// Unrecognized event
    UnrecognizedEvent(ReceiverSessionEvent),
}

#[derive(Debug, Clone)]
pub enum ReceiverState {
    Uninitialized(UninitializedReceiver),
    WithContext(ReceiverWithContext),
    UncheckedProposal(UncheckedProposal),
    MaybeInputsOwned(MaybeInputsOwned),
    MaybeInputsSeen(MaybeInputsSeen),
    OutputsUnknown(OutputsUnknown),
    WantsOutputs(WantsOutputs),
    WantsInputs(WantsInputs),
    ProvisionalProposal(ProvisionalProposal),
    PayjoinProposal(PayjoinProposal),
}

impl State for ReceiverState {
    fn into_receiver<P>(self, persister: P) -> Receiver<Self, P>
    where
        P: PersistedSession + Clone,
        P::SessionEvent: From<ReceiverSessionEvent>,
    {
        Receiver { persister, state: self }
    }

    fn into_receiver_state(self) -> ReceiverState { self }
}

impl ReceiverState {
    fn process_event(&self, event: ReceiverSessionEvent) -> ReceiverState {
        match (&self, event) {
            (ReceiverState::Uninitialized(_), ReceiverSessionEvent::Created(context)) => {
                println!("Created context: {:?}", context);
                ReceiverState::WithContext(ReceiverWithContext { context })
            }

            (
                ReceiverState::WithContext(state),
                ReceiverSessionEvent::UncheckedProposal(proposal),
            ) => state.apply_unchecked_from_payload(proposal),

            (
                ReceiverState::UncheckedProposal(state),
                ReceiverSessionEvent::MaybeInputsOwned(inputs),
            ) => state.apply_maybe_inputs_owned(inputs),

            (
                ReceiverState::MaybeInputsOwned(state),
                ReceiverSessionEvent::MaybeInputsSeen(maybe_inputs_seen),
            ) => state.apply_maybe_inputs_seen(maybe_inputs_seen),

            (
                ReceiverState::MaybeInputsSeen(state),
                ReceiverSessionEvent::OutputsUnknown(outputs_unknown),
            ) => state.apply_outputs_unknown(outputs_unknown),

            (
                ReceiverState::OutputsUnknown(state),
                ReceiverSessionEvent::WantsOutputs(wants_outputs),
            ) => state.apply_wants_outputs(wants_outputs),

            (
                ReceiverState::WantsOutputs(state),
                ReceiverSessionEvent::WantsInputs(wants_inputs),
            ) => state.apply_wants_inputs(wants_inputs),

            (
                ReceiverState::WantsInputs(state),
                ReceiverSessionEvent::ProvisionalProposal(provisional_proposal),
            ) => state.apply_provisional_proposal(provisional_proposal),

            (
                ReceiverState::ProvisionalProposal(state),
                ReceiverSessionEvent::PayjoinProposal(payjoin_proposal),
            ) => state.apply_payjoin_proposal(payjoin_proposal),

            // TODO: Handle invalid transitions with a catch-all that provides better error info
            (current_state, event) => {
                panic!("Invalid state transition from {:?} with event {:?}", current_state, event);
            }
        }
    }
}

#[derive(Default, Clone)]
pub struct SessionHistory {
    events: Vec<ReceiverSessionEvent>,
}

impl SessionHistory {
    pub fn replay_receiver_event_log<P>(
        &mut self,
        persister: P,
    ) -> Result<ReceiverState, ReceiverReplayError>
    where
        P: PersistedSession + Clone,
        P::SessionEvent: From<ReceiverSessionEvent>,
        ReceiverSessionEvent: From<P::SessionEvent>,
    {
        let logs = persister
            .load()
            .map_err(|_| ReceiverReplayError::SessionInvalid("No good".to_string()))?;
        let mut receiver = ReceiverState::Uninitialized(UninitializedReceiver {});

        for log in logs {
            self.events.push(log.clone().into());
            receiver = receiver.process_event(log.into());
        }

        Ok(receiver)
    }

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
pub struct Receiver<State, P> {
    state: State,
    persister: P,
}

impl<S, P> Receiver<S, P>
where
    P: PersistedSession + Clone,
    P::SessionEvent: From<ReceiverSessionEvent>,
    S: State,
{
    pub fn into_receiver_state(self) -> ReceiverState { self.state.into_receiver_state() }
    pub fn from_receiver_state(state: S, persister: P) -> Self { Self { persister, state } }
}

pub trait State: Clone {
    /// Convert receiver state into a enum representation
    fn into_receiver_state(self) -> ReceiverState;
    /// Convert receiver state into a receiver that is generic over the state and persister
    fn into_receiver<P>(self, persister: P) -> Receiver<Self, P>
    where
        P: PersistedSession + Clone,
        P::SessionEvent: From<ReceiverSessionEvent>,
    {
        Receiver { persister, state: self }
    }
}

#[derive(Debug, Clone)]
/// The receiver is not initialized yet, no session context is available yet
pub struct UninitializedReceiver {}

impl State for UninitializedReceiver {
    fn into_receiver_state(self) -> ReceiverState { ReceiverState::Uninitialized(self) }
}

impl<P> Receiver<UninitializedReceiver, P>
where
    P: PersistedSession + Clone,
    P::SessionEvent: From<ReceiverSessionEvent>,
{
    pub fn create_session(
        address: Address,
        directory: impl IntoUrl,
        ohttp_keys: OhttpKeys,
        expire_after: Option<Duration>,
        persister: P,
    ) -> Result<Receiver<ReceiverWithContext, P>, IntoUrlError> {
        let session_context = SessionContext {
            address,
            directory: directory.into_url()?,
            subdirectory: None,
            ohttp_keys,
            expiry: SystemTime::now() + expire_after.unwrap_or(TWENTY_FOUR_HOURS_DEFAULT_EXPIRY),
            s: HpkeKeyPair::gen_keypair(),
            e: None,
        };
        persister.save(ReceiverSessionEvent::Created(session_context.clone()).into()).unwrap();
        Ok(Receiver { persister, state: ReceiverWithContext { context: session_context } })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiverWithContext {
    context: SessionContext,
}
impl State for ReceiverWithContext {
    fn into_receiver_state(self) -> ReceiverState { ReceiverState::WithContext(self) }

    fn into_receiver<P>(self, persister: P) -> Receiver<Self, P>
    where
        P: PersistedSession + Clone,
        P::SessionEvent: From<ReceiverSessionEvent>,
    {
        Receiver { persister, state: self }
    }
}

impl<P> Receiver<ReceiverWithContext, P>
where
    P: PersistedSession + Clone,
    P::SessionEvent: From<ReceiverSessionEvent>,
{
    /// Extract an OHTTP Encapsulated HTTP GET request for the Original PSBT
    pub fn extract_req(
        &mut self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, ohttp::ClientResponse), Error> {
        if SystemTime::now() > self.state.context.expiry {
            return Err(InternalSessionError::Expired(self.state.context.expiry).into());
        }
        let (body, ohttp_ctx) =
            self.fallback_req_body().map_err(InternalSessionError::OhttpEncapsulation)?;
        let req = Request::new_v2(&self.state.context.full_relay_url(ohttp_relay)?, &body);
        Ok((req, ohttp_ctx))
    }

    pub fn process_res(
        &mut self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> Result<Option<Receiver<UncheckedProposal, P>>, Error> {
        let res = self.inner_process_res(body, context)?;
        if let Some(proposal) = res {
            // TODO: remove unwrap
            self.persister
                .save(ReceiverSessionEvent::UncheckedProposal(proposal.clone()).into())
                .unwrap();
            Ok(Some(Receiver {
                persister: self.persister.clone(),
                state: UncheckedProposal { v1: proposal, context: self.state.context.clone() },
            }))
        } else {
            Ok(None)
        }
    }

    /// The response can either be an UncheckedProposal or an ACCEPTED message
    /// indicating no UncheckedProposal is available yet.
    fn inner_process_res(
        &mut self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> Result<Option<v1::UncheckedProposal>, Error> {
        let response_array: &[u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES] =
            body.try_into()
                .map_err(|_| InternalSessionError::UnexpectedResponseSize(body.len()))?;
        log::trace!("decapsulating directory response");
        let response = ohttp_decapsulate(context, response_array)
            .map_err(InternalSessionError::OhttpEncapsulation)?;
        if response.body().is_empty() {
            log::debug!("response is empty");
            return Ok(None);
        }
        match String::from_utf8(response.body().to_vec()) {
            // V1 response bodies are utf8 plaintext
            Ok(response) => Ok(Some(self.extract_proposal_from_v1(response)?)),
            // V2 response bodies are encrypted binary
            Err(_) => Ok(Some(self.extract_proposal_from_v2(response.body().to_vec())?)),
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
        &mut self,
        response: String,
    ) -> Result<v1::UncheckedProposal, ReplyableError> {
        self.unchecked_from_payload(response)
    }

    fn extract_proposal_from_v2(
        &mut self,
        response: Vec<u8>,
    ) -> Result<v1::UncheckedProposal, Error> {
        let (payload_bytes, e) =
            decrypt_message_a(&response, self.state.context.s.secret_key().clone())?;
        self.state.context.e = Some(e);
        let payload = String::from_utf8(payload_bytes)
            .map_err(|e| Error::ReplyToSender(InternalPayloadError::Utf8(e).into()))?;
        self.unchecked_from_payload(payload).map_err(Error::ReplyToSender)
    }

    fn unchecked_from_payload(
        &mut self,
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
}

impl ReceiverWithContext {
    pub fn apply_unchecked_from_payload(&self, event: v1::UncheckedProposal) -> ReceiverState {
        let new_state = UncheckedProposal { v1: event, context: self.context.clone() };

        ReceiverState::UncheckedProposal(new_state)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UncheckedProposal {
    pub(crate) v1: v1::UncheckedProposal,
    pub(crate) context: SessionContext,
}

impl State for UncheckedProposal {
    fn into_receiver_state(self) -> ReceiverState { ReceiverState::UncheckedProposal(self) }
}

impl<P> Receiver<UncheckedProposal, P>
where
    P: PersistedSession + Clone,
    P::SessionEvent: From<ReceiverSessionEvent>,
{
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
        &self,
        min_fee_rate: Option<FeeRate>,
        can_broadcast: impl Fn(&bitcoin::Transaction) -> Result<bool, ImplementationError>,
    ) -> Result<Receiver<MaybeInputsOwned, P>, ReplyableError> {
        let v1 =
            match self.state.v1.clone().check_broadcast_suitability(min_fee_rate, can_broadcast) {
                Ok(v1) => {
                    // TODO: remove unwrap
                    self.persister
                        .save(ReceiverSessionEvent::MaybeInputsOwned(v1.clone()).into())
                        .unwrap();
                    v1
                }
                Err(e) => {
                    self.persister.record_error(&e).unwrap();
                    return Err(e);
                }
            };
        Ok(Receiver {
            persister: self.persister.clone(),
            state: MaybeInputsOwned { v1, context: self.state.context.clone() },
        })
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
    pub fn assume_interactive_receiver(self) -> Receiver<MaybeInputsOwned, P> {
        let inner = self.state.v1.assume_interactive_receiver();
        Receiver {
            persister: self.persister,
            state: MaybeInputsOwned { v1: inner, context: self.state.context },
        }
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

    /// The per-session identifier
    pub fn id(&self) -> ShortId { id(&self.state.context.s) }
}

impl UncheckedProposal {
    pub fn apply_maybe_inputs_owned(&self, v1: v1::MaybeInputsOwned) -> ReceiverState {
        let new_state = MaybeInputsOwned { v1, context: self.context.clone() };
        ReceiverState::MaybeInputsOwned(new_state)
    }
}

#[derive(Debug, Clone)]
pub struct MaybeInputsOwned {
    v1: v1::MaybeInputsOwned,
    context: SessionContext,
}

impl State for MaybeInputsOwned {
    fn into_receiver_state(self) -> ReceiverState { ReceiverState::MaybeInputsOwned(self) }
}

impl<P> Receiver<MaybeInputsOwned, P>
where
    P: PersistedSession + Clone,
    P::SessionEvent: From<ReceiverSessionEvent>,
{
    /// Check that the Original PSBT has no receiver-owned inputs.
    /// Return original-psbt-rejected error or otherwise refuse to sign undesirable inputs.
    ///
    /// An attacker could try to spend receiver's own inputs. This check prevents that.
    pub fn check_inputs_not_owned(
        self,
        is_owned: impl Fn(&Script) -> Result<bool, ImplementationError>,
    ) -> Result<Receiver<MaybeInputsSeen, P>, ReplyableError> {
        let inner = match self.state.v1.clone().check_inputs_not_owned(is_owned) {
            Ok(inner) => inner,
            Err(e) => {
                self.persister.record_error(&e).unwrap();
                return Err(e);
            }
        };
        // TODO: remove unwrap
        self.persister.save(ReceiverSessionEvent::MaybeInputsSeen(inner.clone()).into()).unwrap();
        Ok(Receiver {
            persister: self.persister.clone(),
            state: MaybeInputsSeen { v1: inner, context: self.state.context.clone() },
        })
    }
}

impl MaybeInputsOwned {
    pub fn apply_maybe_inputs_seen(&self, v1: v1::MaybeInputsSeen) -> ReceiverState {
        let new_state = MaybeInputsSeen { v1, context: self.context.clone() };
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

impl State for MaybeInputsSeen {
    fn into_receiver_state(self) -> ReceiverState { ReceiverState::MaybeInputsSeen(self) }
}

impl<P> Receiver<MaybeInputsSeen, P>
where
    P: PersistedSession + Clone,
    P::SessionEvent: From<ReceiverSessionEvent>,
{
    /// Make sure that the original transaction inputs have never been seen before.
    /// This prevents probing attacks. This prevents reentrant Payjoin, where a sender
    /// proposes a Payjoin PSBT as a new Original PSBT for a new Payjoin.
    pub fn check_no_inputs_seen_before(
        self,
        is_known: impl Fn(&OutPoint) -> Result<bool, ImplementationError>,
    ) -> Result<Receiver<OutputsUnknown, P>, ReplyableError> {
        let inner = match self.state.v1.clone().check_no_inputs_seen_before(is_known) {
            Ok(inner) => inner,
            Err(e) => {
                self.persister.record_error(&e).unwrap();
                return Err(e);
            }
        };
        // TODO: remove unwrap
        self.persister.save(ReceiverSessionEvent::OutputsUnknown(inner.clone()).into()).unwrap();
        Ok(Receiver {
            persister: self.persister.clone(),
            state: OutputsUnknown { v1: inner, context: self.state.context.clone() },
        })
    }
}

impl MaybeInputsSeen {
    pub fn apply_outputs_unknown(&self, v1: v1::OutputsUnknown) -> ReceiverState {
        let new_state = OutputsUnknown { v1, context: self.context.clone() };
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

impl State for OutputsUnknown {
    fn into_receiver_state(self) -> ReceiverState { ReceiverState::OutputsUnknown(self) }
}

impl<P> Receiver<OutputsUnknown, P>
where
    P: PersistedSession + Clone,
    P::SessionEvent: From<ReceiverSessionEvent>,
{
    /// Find which outputs belong to the receiver
    pub fn identify_receiver_outputs(
        self,
        is_receiver_output: impl Fn(&Script) -> Result<bool, ImplementationError>,
    ) -> Result<Receiver<WantsOutputs, P>, ReplyableError> {
        let inner = match self.state.v1.clone().identify_receiver_outputs(is_receiver_output) {
            Ok(inner) => inner,
            Err(e) => {
                self.persister.record_error(&e).unwrap();
                return Err(e);
            }
        };
        // TODO: remove unwrap
        self.persister.save(ReceiverSessionEvent::WantsOutputs(inner.clone()).into()).unwrap();
        Ok(Receiver {
            persister: self.persister.clone(),
            state: WantsOutputs { v1: inner, context: self.state.context.clone() },
        })
    }
}

impl OutputsUnknown {
    pub fn apply_wants_outputs(&self, v1: v1::WantsOutputs) -> ReceiverState {
        let new_state = WantsOutputs { v1, context: self.context.clone() };
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

impl State for WantsOutputs {
    fn into_receiver_state(self) -> ReceiverState { ReceiverState::WantsOutputs(self) }
}

impl<P> Receiver<WantsOutputs, P>
where
    P: PersistedSession + Clone,
    P::SessionEvent: From<ReceiverSessionEvent>,
{
    /// Whether the receiver is allowed to substitute original outputs or not.
    pub fn output_substitution(&self) -> OutputSubstitution { self.state.v1.output_substitution() }

    /// Substitute the receiver output script with the provided script.
    pub fn substitute_receiver_script(
        self,
        output_script: &Script,
    ) -> Result<Self, OutputSubstitutionError> {
        let inner = self.state.v1.substitute_receiver_script(output_script)?;
        Ok(Receiver {
            persister: self.persister.clone(),
            state: WantsOutputs { v1: inner, context: self.state.context.clone() },
        })
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
        Ok(Receiver {
            persister: self.persister.clone(),
            state: WantsOutputs { v1: inner, context: self.state.context.clone() },
        })
    }

    /// Proceed to the input contribution step.
    /// Outputs cannot be modified after this function is called.
    pub fn commit_outputs(self) -> Receiver<WantsInputs, P> {
        let inner = self.state.v1.clone().commit_outputs();
        self.persister.save(ReceiverSessionEvent::WantsInputs(inner.clone()).into()).unwrap();
        Receiver {
            persister: self.persister.clone(),
            state: WantsInputs { v1: inner, context: self.state.context.clone() },
        }
    }
}

impl WantsOutputs {
    pub fn apply_wants_inputs(&self, v1: v1::WantsInputs) -> ReceiverState {
        let new_state = WantsInputs { v1, context: self.context.clone() };
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

impl State for WantsInputs {
    fn into_receiver_state(self) -> ReceiverState { ReceiverState::WantsInputs(self) }
}

impl<P> Receiver<WantsInputs, P>
where
    P: PersistedSession + Clone,
    P::SessionEvent: From<ReceiverSessionEvent>,
{
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
        Ok(Receiver {
            persister: self.persister.clone(),
            state: WantsInputs { v1: inner, context: self.state.context.clone() },
        })
    }

    /// Proceed to the proposal finalization step.
    /// Inputs cannot be modified after this function is called.
    pub fn commit_inputs(self) -> Receiver<ProvisionalProposal, P> {
        let inner = self.state.v1.clone().commit_inputs();
        self.persister
            .save(ReceiverSessionEvent::ProvisionalProposal(inner.clone()).into())
            .unwrap();
        Receiver {
            persister: self.persister.clone(),
            state: ProvisionalProposal { v1: inner, context: self.state.context.clone() },
        }
    }
}

impl WantsInputs {
    pub fn apply_provisional_proposal(&self, v1: v1::ProvisionalProposal) -> ReceiverState {
        let new_state = ProvisionalProposal { v1, context: self.context.clone() };
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

impl State for ProvisionalProposal {
    fn into_receiver_state(self) -> ReceiverState { ReceiverState::ProvisionalProposal(self) }
}

impl<P> Receiver<ProvisionalProposal, P>
where
    P: PersistedSession + Clone,
    P::SessionEvent: From<ReceiverSessionEvent>,
{
    pub fn finalize_proposal(
        self,
        wallet_process_psbt: impl Fn(&Psbt) -> Result<Psbt, ImplementationError>,
        min_fee_rate: Option<FeeRate>,
        max_effective_fee_rate: Option<FeeRate>,
    ) -> Result<Receiver<PayjoinProposal, P>, ReplyableError> {
        let inner = match self.state.v1.clone().finalize_proposal(
            wallet_process_psbt,
            min_fee_rate,
            max_effective_fee_rate,
        ) {
            Ok(inner) => inner,
            Err(e) => {
                // TODO: remove unwrap
                // TODO: are all errors here terminal?
                self.persister.record_error(&e).unwrap();
                return Err(e);
            }
        };
        // TODO: remove unwrap
        self.persister.save(ReceiverSessionEvent::PayjoinProposal(inner.clone()).into()).unwrap();
        Ok(Receiver {
            persister: self.persister.clone(),
            state: PayjoinProposal { v1: inner, context: self.state.context.clone() },
        })
    }
}

impl ProvisionalProposal {
    pub fn apply_payjoin_proposal(&self, v1: v1::PayjoinProposal) -> ReceiverState {
        let new_state = PayjoinProposal { v1, context: self.context.clone() };
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

impl State for PayjoinProposal {
    fn into_receiver_state(self) -> ReceiverState { ReceiverState::PayjoinProposal(self) }
}

impl PayjoinProposal {
    #[cfg(feature = "_multiparty")]
    pub(crate) fn new(v1: v1::PayjoinProposal, context: SessionContext) -> Self {
        Self { v1, context }
    }
}

impl<P> Receiver<PayjoinProposal, P>
where
    P: PersistedSession + Clone,
    P::SessionEvent: From<ReceiverSessionEvent>,
{
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
        &self,
        res: &[u8],
        ohttp_context: ohttp::ClientResponse,
    ) -> Result<(), Error> {
        let response_array: &[u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES] =
            res.try_into().map_err(|_| InternalSessionError::UnexpectedResponseSize(res.len()))?;
        let res = ohttp_decapsulate(ohttp_context, response_array)
            .map_err(InternalSessionError::OhttpEncapsulation)?;
        if res.status().is_success() {
            // TODO: remove unwraps
            self.persister.close().unwrap();
            Ok(())
        } else {
            Err(InternalSessionError::UnexpectedStatusCode(res.status()).into())
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
    fn debugging_test() {
        #[derive(Clone)]
        pub struct NoopPersister;

        impl PersistedSession for NoopPersister {
            type SessionEvent = ReceiverSessionEvent;
            type Error = ReplyableError;

            fn save(&self, event: Self::SessionEvent) -> Result<(), Self::Error> { Ok(()) }

            fn load(&self) -> Result<Box<dyn Iterator<Item = Self::SessionEvent>>, Self::Error> {
                Ok(Box::new(std::iter::empty()))
            }

            fn close(&self) -> Result<(), Self::Error> { Ok(()) }
        }

        let ohttp_keys =
            OhttpKeys::from_str("OH1QYPEKJA0N5XWWJAQQ83JCSKZSJ8QKJYLR77QVU6UKA48C0EJSSJ07PG")
                .unwrap();
        println!("Test initialized with OHTTP keys: {:?}", ohttp_keys);

        let address =
            Address::from_str("2MuyMrZHkbHbfjudmKUy45dU4P17pjG2szK").unwrap().assume_checked();
        let directory = EXAMPLE_URL.clone();
        let mut receiver = UninitializedReceiver::create_session(
            address,
            directory.clone(),
            ohttp_keys,
            None,
            NoopPersister,
        )
        .unwrap();

        println!("Created receiver with directory: {}", directory);
        let pj_uri = receiver.pj_uri();
        println!("Generated PJ URI: {:?}", pj_uri);

        let sender = crate::send::v2::SenderBuilder::new(
            Psbt::from_str(payjoin_test_utils::ORIGINAL_PSBT).unwrap(),
            pj_uri,
        )
        .build_recommended(FeeRate::BROADCAST_MIN)
        .unwrap()
        .build();
        let (req, ctx) = sender.extract_v2(EXAMPLE_URL.clone()).unwrap();
        println!("Extracted sender request with body length: {}", req.body.len());

        let (recv_req, ohttp_ctx) = receiver.extract_req(EXAMPLE_URL.clone()).unwrap();
        println!("Extracted receiver request with body length: {}", recv_req.body.len());

        receiver.process_res(&req.body, ohttp_ctx, NoopPersister).unwrap();
    }

    #[test]
    fn default_expiry() {
        let now = SystemTime::now();

        let session = NewReceiver::new(
            SHARED_CONTEXT.address.clone(),
            SHARED_CONTEXT.directory.clone(),
            SHARED_CONTEXT.ohttp_keys.clone(),
            None,
        );
        let session_expiry = session.unwrap().context.expiry.duration_since(now).unwrap().as_secs();
        let default_expiry = Duration::from_secs(86400);
        if let Some(expected_expiry) = now.checked_add(default_expiry) {
            assert_eq!(TWENTY_FOUR_HOURS_DEFAULT_EXPIRY, default_expiry);
            assert_eq!(session_expiry, expected_expiry.duration_since(now).unwrap().as_secs());
        }
    }

    #[test]
    fn receiver_ser_de_roundtrip() -> Result<(), serde_json::Error> {
        let session = Receiver { context: SHARED_CONTEXT.clone() };
        let short_id = id(&session.context.s);
        assert_eq!(session.key().as_ref(), short_id.as_bytes());
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

    //     let server_error = || {
    //         proposal
    //             .clone()
    //             .check_broadcast_suitability(None, |_| Err("mock error".into()))
    //             .expect_err("expected broadcast suitability check to fail")
    //     };

    //     let expected_json = serde_json::json!({
    //         "errorCode": "unavailable",
    //         "message": "Receiver error"
    //     });

    //     let actual_json = JsonReply::from(server_error()).to_json().clone();
    //     assert_eq!(actual_json, expected_json);

    //     let (_req, _ctx) =
    //         proposal.clone().extract_err_req(&server_error().into(), &*EXAMPLE_URL)?;

    //     let internal_error: ReplyableError = InternalPayloadError::MissingPayment.into();
    //     let (_req, _ctx) = proposal.extract_err_req(&internal_error.into(), &*EXAMPLE_URL)?;
    //     Ok(())
    // }

    // #[test]
    // fn receiver_ser_de_roundtrip() -> Result<(), serde_json::Error> {
    //     let session = Receiver { context: SHARED_CONTEXT.clone() };
    //     let serialized = serde_json::to_string(&session)?;
    //     let deserialized: Receiver = serde_json::from_str(&serialized)?;
    //     assert_eq!(session, deserialized);
    //     Ok(())
    // }

    // #[test]
    // fn test_v2_pj_uri() {
    //     let uri = Receiver { context: SHARED_CONTEXT.clone() }.pj_uri();
    //     assert_ne!(uri.extras.endpoint, EXAMPLE_URL.clone());
    //     assert_eq!(uri.extras.output_substitution, OutputSubstitution::Enabled);
    // }
}
