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
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::psbt::Psbt;
use bitcoin::{Address, Amount, FeeRate, OutPoint, Script, TxOut, Txid};
pub use error::{CreateRequestError, SessionError};
pub(crate) use error::{InternalCreateRequestError, InternalSessionError};
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
pub use session::{
    replay_event_log, replay_event_log_async, SessionEvent, SessionHistory, SessionOutcome,
    SessionStatus,
};
#[cfg(target_arch = "wasm32")]
use web_time::Duration;

use self::sealed::FallbackTx;
use super::error::{Error, InputContributionError};
use super::{
    common, CoinSelectionError, InternalPayloadError, JsonReply, OutputSubstitutionError,
    ProtocolError,
};
use crate::core::Url;
use crate::error::{InternalReplayError, ReplayError};
use crate::hpke::{decrypt_message_a, encrypt_message_b, HpkeKeyPair, HpkePublicKey};
use crate::ohttp::{
    ohttp_encapsulate, process_get_res, process_post_res, OhttpEncapsulationError, OhttpKeys,
    OhttpResponse,
};
use crate::output_substitution::OutputSubstitution;
use crate::persist::{
    MaybeFatalOrSuccessTransition, MaybeFatalTransition, MaybeFatalTransitionWithNoResults,
    MaybeTerminalSuccessTransition, MaybeTerminalTransition, MaybeTransientTransition,
    NextStateTransition, TerminalTransition,
};
use crate::receive::{parse_payload, InputPair, OriginalPayload, PsbtContext};
use crate::time::Time;
use crate::uri::ShortId;
use crate::{ImplementationError, IntoUrl, IntoUrlError, Request, Version};

mod error;
mod session;

const SUPPORTED_VERSIONS: &[Version] = &[Version::One, Version::Two];

static TWENTY_FOUR_HOURS_DEFAULT_EXPIRATION: Duration = Duration::from_secs(60 * 60 * 24);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionContext {
    #[serde(deserialize_with = "deserialize_address_assume_checked")]
    address: Address,
    directory: Url,
    ohttp_keys: OhttpKeys,
    expiration: Time,
    amount: Option<Amount>,
    receiver_key: HpkeKeyPair,
    reply_key: Option<HpkePublicKey>,
    max_fee_rate: FeeRate,
}

impl SessionContext {
    fn full_relay_url(&self, ohttp_relay: impl IntoUrl) -> Result<Url, crate::into_url::Error> {
        let relay_base = ohttp_relay.into_url()?;

        // Only reveal scheme and authority to the relay
        let directory_base = self.directory.join("/")?;

        // Append that information as a path to the relay URL
        Ok(relay_base.join(&format!("/{directory_base}"))?)
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
/// Each variant parameterizes a `Receiver` with a specific state type.
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
    HasReplyableError(Receiver<HasReplyableError>),
    Monitor(Receiver<Monitor>),
    PendingFallback(Receiver<PendingFallback>),
    Closed(SessionOutcome),
}

impl ReceiveSession {
    fn new(context: SessionContext) -> Self {
        ReceiveSession::Initialized(Receiver { state: Initialized {}, session_context: context })
    }

    fn process_event(
        self,
        event: SessionEvent,
    ) -> Result<ReceiveSession, ReplayError<Self, SessionEvent>> {
        match (self, event) {
            (
                ReceiveSession::Initialized(state),
                SessionEvent::RetrievedOriginalPayload { original: proposal, reply_key },
            ) => Ok(state.apply_retrieved_original_payload(proposal, reply_key)),

            (
                ReceiveSession::UncheckedOriginalPayload(state),
                SessionEvent::CheckedBroadcastSuitability(),
            ) => Ok(state.apply_checked_broadcast_suitability()),

            (ReceiveSession::MaybeInputsOwned(state), SessionEvent::CheckedInputsNotOwned()) =>
                Ok(state.apply_checked_inputs_not_owned()),

            (ReceiveSession::MaybeInputsSeen(state), SessionEvent::CheckedNoInputsSeenBefore()) =>
                Ok(state.apply_checked_no_inputs_seen_before()),

            (
                ReceiveSession::OutputsUnknown(state),
                SessionEvent::IdentifiedReceiverOutputs(owned_vouts),
            ) => state.apply_identified_receiver_outputs(owned_vouts),

            (
                ReceiveSession::WantsOutputs(state),
                SessionEvent::CommittedOutputs { outputs, change_vout },
            ) => state.apply_committed_outputs(outputs, change_vout),

            (
                ReceiveSession::WantsInputs(state),
                SessionEvent::CommittedInputs { receiver_inputs, payjoin_psbt },
            ) => state.apply_committed_inputs(receiver_inputs, payjoin_psbt),

            (ReceiveSession::WantsFeeRange(state), SessionEvent::AppliedFeeRange(psbt_context)) =>
                Ok(state.apply_applied_fee_range(psbt_context)),

            (
                ReceiveSession::ProvisionalProposal(state),
                SessionEvent::FinalizedProposal(payjoin_proposal),
            ) => Ok(state.apply_payjoin_proposal(payjoin_proposal)),

            (ReceiveSession::PayjoinProposal(state), SessionEvent::PostedPayjoinProposal()) =>
                Ok(state.apply_payjoin_posted()),

            (session, SessionEvent::Cancelled) =>
                try_pending_fallback(session).map_err(|session| {
                    InternalReplayError::InvalidEvent(
                        Box::new(SessionEvent::Cancelled),
                        Some(session),
                    )
                    .into()
                }),

            (session, SessionEvent::ProtocolFailed) =>
                try_pending_fallback(session).map_err(|session| {
                    InternalReplayError::InvalidEvent(
                        Box::new(SessionEvent::ProtocolFailed),
                        Some(session),
                    )
                    .into()
                }),

            (_, SessionEvent::Closed(session_outcome)) =>
                Ok(ReceiveSession::Closed(session_outcome)),

            (session, SessionEvent::GotReplyableError(error)) => {
                let (session_context, fallback_tx) = match session {
                    ReceiveSession::Initialized(r) => (r.session_context, None),
                    ReceiveSession::UncheckedOriginalPayload(r) => (r.session_context, None),
                    ReceiveSession::MaybeInputsOwned(r) =>
                        (r.session_context, Some(r.state.fallback_tx())),
                    ReceiveSession::MaybeInputsSeen(r) =>
                        (r.session_context, Some(r.state.fallback_tx())),
                    ReceiveSession::OutputsUnknown(r) =>
                        (r.session_context, Some(r.state.fallback_tx())),
                    ReceiveSession::WantsOutputs(r) =>
                        (r.session_context, Some(r.state.fallback_tx())),
                    ReceiveSession::WantsInputs(r) =>
                        (r.session_context, Some(r.state.fallback_tx())),
                    ReceiveSession::WantsFeeRange(r) =>
                        (r.session_context, Some(r.state.fallback_tx())),
                    ReceiveSession::ProvisionalProposal(r) =>
                        (r.session_context, Some(r.state.fallback_tx())),
                    ReceiveSession::PayjoinProposal(r) =>
                        (r.session_context, Some(r.state.fallback_tx())),
                    ReceiveSession::HasReplyableError(r) =>
                        (r.session_context, r.state.fallback_tx.clone()),
                    ReceiveSession::Monitor(r) => (r.session_context, Some(r.state.fallback_tx())),
                    ReceiveSession::PendingFallback(r) => {
                        let fallback_tx = r.fallback_tx().clone();
                        (r.session_context, Some(fallback_tx))
                    }
                    ReceiveSession::Closed(session_outcome) =>
                        return Ok(ReceiveSession::Closed(session_outcome)),
                };

                Ok(ReceiveSession::HasReplyableError(Receiver {
                    state: HasReplyableError { error_reply: error, fallback_tx },
                    session_context,
                }))
            }

            (current_state, event) => Err(InternalReplayError::InvalidEvent(
                Box::new(event),
                Some(Box::new(current_state)),
            )
            .into()),
        }
    }
}

/// Payload validation failure for an otherwise well-sequenced replay event.
///
/// The event log is not trusted to uphold the live path's invariants: it is
/// deserialized from application storage, and a malformed payload would panic
/// in later typestates if applied unchecked.
fn invalid_event_payload(
    event: SessionEvent,
    reason: String,
) -> ReplayError<ReceiveSession, SessionEvent> {
    InternalReplayError::InvalidEventPayload(Box::new(event), reason).into()
}

fn pending_fallback_from<S: HasFallbackTx>(r: Receiver<S>) -> ReceiveSession {
    let fallback_tx = r.state.fallback_tx();
    ReceiveSession::PendingFallback(Receiver {
        state: PendingFallback { fallback_tx },
        session_context: r.session_context,
    })
}

fn pending_fallback_from_replyable_error(
    r: Receiver<HasReplyableError>,
) -> Result<ReceiveSession, Box<ReceiveSession>> {
    let Receiver { state: HasReplyableError { error_reply, fallback_tx }, session_context } = r;
    match fallback_tx {
        Some(fallback_tx) => Ok(ReceiveSession::PendingFallback(Receiver {
            state: PendingFallback { fallback_tx },
            session_context,
        })),
        None => Err(Box::new(ReceiveSession::HasReplyableError(Receiver {
            state: HasReplyableError { error_reply, fallback_tx: None },
            session_context,
        }))),
    }
}

fn try_pending_fallback(session: ReceiveSession) -> Result<ReceiveSession, Box<ReceiveSession>> {
    match session {
        ReceiveSession::MaybeInputsOwned(receiver) => Ok(pending_fallback_from(receiver)),
        ReceiveSession::MaybeInputsSeen(receiver) => Ok(pending_fallback_from(receiver)),
        ReceiveSession::OutputsUnknown(receiver) => Ok(pending_fallback_from(receiver)),
        ReceiveSession::WantsOutputs(receiver) => Ok(pending_fallback_from(receiver)),
        ReceiveSession::WantsInputs(receiver) => Ok(pending_fallback_from(receiver)),
        ReceiveSession::WantsFeeRange(receiver) => Ok(pending_fallback_from(receiver)),
        ReceiveSession::ProvisionalProposal(receiver) => Ok(pending_fallback_from(receiver)),
        ReceiveSession::PayjoinProposal(receiver) => Ok(pending_fallback_from(receiver)),
        ReceiveSession::HasReplyableError(receiver) =>
            pending_fallback_from_replyable_error(receiver),
        ReceiveSession::Monitor(receiver) => Ok(pending_fallback_from(receiver)),
        session => Err(Box::new(session)),
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
    impl State for super::HasReplyableError {}
    impl State for super::Monitor {}
    impl State for super::PendingFallback {}

    pub trait FallbackTx: State {
        fn fallback_tx(&self) -> bitcoin::Transaction;
    }

    impl FallbackTx for super::MaybeInputsOwned {
        fn fallback_tx(&self) -> bitcoin::Transaction {
            self.original.psbt.clone().extract_tx_unchecked_fee_rate()
        }
    }

    impl FallbackTx for super::MaybeInputsSeen {
        fn fallback_tx(&self) -> bitcoin::Transaction {
            self.original.psbt.clone().extract_tx_unchecked_fee_rate()
        }
    }

    impl FallbackTx for super::OutputsUnknown {
        fn fallback_tx(&self) -> bitcoin::Transaction {
            self.original.psbt.clone().extract_tx_unchecked_fee_rate()
        }
    }

    impl FallbackTx for super::WantsOutputs {
        fn fallback_tx(&self) -> bitcoin::Transaction {
            self.inner.original_psbt().clone().extract_tx_unchecked_fee_rate()
        }
    }

    impl FallbackTx for super::WantsInputs {
        fn fallback_tx(&self) -> bitcoin::Transaction {
            self.inner.original_psbt().clone().extract_tx_unchecked_fee_rate()
        }
    }

    impl FallbackTx for super::WantsFeeRange {
        fn fallback_tx(&self) -> bitcoin::Transaction {
            self.inner.original_psbt().clone().extract_tx_unchecked_fee_rate()
        }
    }

    impl FallbackTx for super::ProvisionalProposal {
        fn fallback_tx(&self) -> bitcoin::Transaction {
            self.psbt_context.original_psbt.clone().extract_tx_unchecked_fee_rate()
        }
    }

    impl FallbackTx for super::PayjoinProposal {
        fn fallback_tx(&self) -> bitcoin::Transaction {
            self.psbt_context.original_psbt.clone().extract_tx_unchecked_fee_rate()
        }
    }

    impl FallbackTx for super::Monitor {
        fn fallback_tx(&self) -> bitcoin::Transaction {
            self.psbt_context.original_psbt.clone().extract_tx_unchecked_fee_rate()
        }
    }
}

/// Sealed trait for V2 receive session states.
///
/// Any typestate should implement this trait to be considered a part of the protocol flow.
/// This trait is sealed to prevent external implementations. Only types within this crate
/// can implement this trait, ensuring type safety and protocol integrity.
pub trait State: sealed::State {}

impl<S: sealed::State> State for S {}

/// Marker trait for receiver protocol states that hold a verified broadcastable
/// fallback transaction.
///
/// This trait is sealed to prevent external implementations.
pub trait HasFallbackTx: sealed::FallbackTx {}

impl<T: sealed::FallbackTx> HasFallbackTx for T {}

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
    pub(crate) session_context: SessionContext,
}

impl<State> core::ops::Deref for Receiver<State> {
    type Target = State;

    fn deref(&self) -> &Self::Target { &self.state }
}

impl<State> core::ops::DerefMut for Receiver<State> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.state }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingFallback {
    fallback_tx: bitcoin::Transaction,
}

/// Typestate holding the fallback transaction after the Payjoin session was cancelled or
/// failed.
///
/// The receiver may broadcast the fallback transaction, then call
/// [`Receiver<PendingFallback>::close`] to close the session.
impl Receiver<PendingFallback> {
    /// Returns the fallback transaction to be broadcast.
    pub fn fallback_tx(&self) -> &bitcoin::Transaction { &self.state.fallback_tx }

    /// Close the Payjoin session.
    ///
    /// Returns a [`TerminalTransition`] that, once successfully persisted, closes the
    /// receiver session.
    pub fn close(self) -> TerminalTransition<SessionEvent, ()> {
        TerminalTransition::new(SessionEvent::Closed(SessionOutcome::Aborted), ())
    }
}

impl<S: HasFallbackTx> Receiver<S> {
    /// Cancel the Payjoin session and return pending fallback handling.
    ///
    /// Returns a [`NextStateTransition`] that, once successfully persisted, yields a
    /// [`Receiver<PendingFallback>`].
    pub fn cancel(self) -> NextStateTransition<SessionEvent, Receiver<PendingFallback>> {
        let fallback_tx = self.state.fallback_tx();
        NextStateTransition::success(
            SessionEvent::Cancelled,
            Receiver {
                state: PendingFallback { fallback_tx },
                session_context: self.session_context,
            },
        )
    }

    /// Whether the payjoin proposal's transaction ID is knowable in advance.
    ///
    /// If every sender input is native SegWit, the sender's final signatures
    /// live in the witness and each script_sig stays empty, so the
    /// transaction ID computed from the unsigned proposal remains valid once
    /// the sender re-signs — the receiver can record it (e.g. to reconcile an
    /// incoming payment) and monitor the network for it.
    ///
    /// If any sender input finalizes with a non-empty script_sig — legacy
    /// inputs, whose signatures live there, but also P2SH-wrapped SegWit
    /// inputs, whose script_sig carries the redeem script push — that
    /// script_sig is part of the txid preimage and changes the transaction
    /// ID. Any transaction ID derived from the proposal before the sender
    /// signs will never appear on the network, and
    /// [`Receiver<Monitor>::check_for_transaction`] concludes the session
    /// without monitoring. Receivers that track payments by transaction ID
    /// can use this to choose a policy up front: decline to contribute and
    /// let the fallback pay, or reconcile that session by script instead of
    /// by transaction ID.
    pub fn proposal_txid_is_stable(&self) -> bool {
        self.state.fallback_tx().input.iter().all(|txin| txin.script_sig.is_empty())
    }
}

impl Receiver<Initialized> {
    /// Cancel the Payjoin session immediately.
    ///
    /// Returns a [`TerminalTransition`] that, once successfully persisted, closes the
    /// receiver session.
    pub fn cancel(self) -> TerminalTransition<SessionEvent, ()> {
        TerminalTransition::new(SessionEvent::Closed(SessionOutcome::Aborted), ())
    }
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
            expiration: Time::from_now(TWENTY_FOUR_HOURS_DEFAULT_EXPIRATION)
                .expect("Default expiration time should be representable as u32 unix time"),
            amount: None,
            reply_key: None,
            max_fee_rate: FeeRate::BROADCAST_MIN,
        };
        Ok(Self(session_context))
    }

    pub fn with_expiration(self, expiration: Duration) -> Self {
        Self(SessionContext {
            expiration: Time::from_now(expiration)
                .expect("specifying expiration as Duration should not fail"),
            ..self.0
        })
    }

    pub fn with_amount(self, amount: Amount) -> Self {
        Self(SessionContext { amount: Some(amount), ..self.0 })
    }

    /// Set the maximum effective fee rate the receiver is willing to pay for their own input/output contributions
    pub fn with_max_fee_rate(self, max_fee_rate: FeeRate) -> Self {
        Self(SessionContext { max_fee_rate, ..self.0 })
    }

    pub fn build(self) -> NextStateTransition<SessionEvent, Receiver<Initialized>> {
        NextStateTransition::success(
            SessionEvent::Created(self.0.clone()),
            Receiver { state: Initialized {}, session_context: self.0 },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Initialized {}

/// The initial typestate of a Payjoin v2 receiver session.
///
/// After sharing the Payjoin URI from [`Receiver<Initialized>::pj_uri`] with the
/// sender out of band, poll the Payjoin Directory in the PJ URI for the sender's
/// Original PSBT: build a request with [`Receiver<Initialized>::create_poll_request`],
/// then pass each response to [`Receiver<Initialized>::process_response`] until it
/// advances to [`Receiver<UncheckedOriginalPayload>`].
impl Receiver<Initialized> {
    /// Construct an OHTTP encapsulated GET request to be used to poll the Payjoin
    /// Directory for the sender's Original PSBT.
    pub fn create_poll_request(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, OhttpResponse), CreateRequestError> {
        if self.session_context.expiration.elapsed() {
            return Err(InternalCreateRequestError::Expired(self.session_context.expiration).into());
        }
        let (body, ohttp_ctx) = self.fallback_req_body()?;
        let req = Request::new_v2(&self.session_context.full_relay_url(ohttp_relay)?, &body);
        Ok((req, OhttpResponse::new(ohttp_ctx)))
    }

    /// Process the Payjoin directory polling response.
    ///
    /// Returns a [`MaybeFatalTransitionWithNoResults`] that, once successfully
    /// persisted, yields either a [`Receiver<UncheckedOriginalPayload>`] if the
    /// sender's Original PSBT is available, or a [`Receiver<Initialized>`] to remain
    /// in stasis if no proposal has arrived yet.
    pub fn process_response(
        self,
        body: &[u8],
        context: OhttpResponse,
    ) -> MaybeFatalTransitionWithNoResults<
        SessionEvent,
        Receiver<UncheckedOriginalPayload>,
        Receiver<Initialized>,
        ProtocolError,
    > {
        let current_state = self.clone();
        let proposal = match self.inner_process_res(body, context.into_inner()) {
            Ok(proposal) => proposal,
            Err(e) => match e {
                ProtocolError::V2(SessionError(InternalSessionError::DirectoryResponse(
                    ref directory_error,
                ))) =>
                    if directory_error.is_fatal() {
                        return MaybeFatalTransitionWithNoResults::fatal(
                            SessionEvent::Closed(SessionOutcome::Aborted),
                            e,
                        );
                    } else {
                        return MaybeFatalTransitionWithNoResults::transient(e, current_state);
                    },
                _ =>
                    return MaybeFatalTransitionWithNoResults::fatal(
                        SessionEvent::Closed(SessionOutcome::Aborted),
                        e,
                    ),
            },
        };

        if let Some((proposal, reply_key)) = proposal {
            MaybeFatalTransitionWithNoResults::success(
                SessionEvent::RetrievedOriginalPayload {
                    original: proposal.clone(),
                    reply_key: reply_key.clone(),
                },
                Receiver {
                    state: UncheckedOriginalPayload { original: proposal },
                    session_context: SessionContext { reply_key, ..current_state.session_context },
                },
            )
        } else {
            MaybeFatalTransitionWithNoResults::no_results(current_state)
        }
    }

    fn inner_process_res(
        self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> Result<Option<(OriginalPayload, Option<HpkePublicKey>)>, ProtocolError> {
        let body = match process_get_res(body, context)
            .map_err(|e| ProtocolError::V2(InternalSessionError::DirectoryResponse(e).into()))?
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
        &self,
    ) -> Result<
        ([u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES], ohttp::ClientResponse),
        OhttpEncapsulationError,
    > {
        let fallback_target = mailbox_endpoint(
            &self.session_context.directory,
            &self.session_context.proposal_mailbox_id(),
        );
        ohttp_encapsulate(&self.session_context.ohttp_keys, "GET", fallback_target.as_str(), None)
    }

    fn extract_proposal_from_v1(self, response: &str) -> Result<OriginalPayload, ProtocolError> {
        self.unchecked_from_payload(response)
    }

    fn extract_proposal_from_v2(
        self,
        response: Vec<u8>,
    ) -> Result<(OriginalPayload, HpkePublicKey), ProtocolError> {
        let (payload_bytes, reply_key) =
            decrypt_message_a(&response, self.session_context.receiver_key.secret_key())
                .map_err(|e| ProtocolError::V2(InternalSessionError::Hpke(e).into()))?;
        let payload = std::str::from_utf8(&payload_bytes)
            .map_err(|e| ProtocolError::OriginalPayload(InternalPayloadError::Utf8(e).into()))?;
        self.unchecked_from_payload(payload).map(|p| (p, reply_key))
    }

    fn unchecked_from_payload(self, payload: &str) -> Result<OriginalPayload, ProtocolError> {
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
    pub fn pj_uri(&self) -> crate::PjUri {
        pj_uri(&self.session_context, OutputSubstitution::Disabled)
    }

    pub(crate) fn apply_retrieved_original_payload(
        self,
        event: OriginalPayload,
        reply_key: Option<HpkePublicKey>,
    ) -> ReceiveSession {
        let new_state = Receiver {
            state: UncheckedOriginalPayload { original: event },
            session_context: SessionContext { reply_key, ..self.session_context },
        };

        ReceiveSession::UncheckedOriginalPayload(new_state)
    }
}

/// This is the first typestate after retrieving the sender's proposal. Here the
/// receiver verifies the Original PSBT is broadcastable so it can serve as a
/// fallback if the payjoin fails.
///
/// Non-interactive receivers (e.g. a donation page that generates a fresh QR code
/// per visit) should call
/// [`Receiver<UncheckedOriginalPayload>::check_broadcast_suitability`] to confirm
/// the proposal is broadcastable (and optionally above a minimum fee rate),
/// guarding against probing attacks that trick the receiver into revealing its
/// UTXOs. Interactive receivers can skip that check and call
/// [`Receiver<UncheckedOriginalPayload>::assume_interactive_receiver`] instead.
/// Either path advances to [`Receiver<MaybeInputsOwned>`].
#[derive(Debug, Clone, PartialEq)]
pub struct UncheckedOriginalPayload {
    pub(crate) original: OriginalPayload,
}

impl Receiver<UncheckedOriginalPayload> {
    /// Cancel the Payjoin session immediately.
    ///
    /// Returns a [`TerminalTransition`] that, once successfully persisted, closes the
    /// receiver session.
    pub fn cancel(self) -> TerminalTransition<SessionEvent, ()> {
        TerminalTransition::new(SessionEvent::Closed(SessionOutcome::Aborted), ())
    }
}

impl Receiver<UncheckedOriginalPayload> {
    /// Check that the sender's Original PSBT is suitable for broadcast, ensuring
    /// it can be used as a fallback if the payjoin does not complete.
    ///
    /// Returns a [`MaybeFatalTransition`] that, once successfully persisted, yields a
    /// [`Receiver<MaybeInputsOwned>`] to continue validation.
    pub fn check_broadcast_suitability(
        self,
        min_fee_rate: Option<FeeRate>,
        can_broadcast: impl Fn(&bitcoin::Transaction) -> Result<bool, ImplementationError>,
    ) -> MaybeFatalTransition<
        SessionEvent,
        Receiver<MaybeInputsOwned>,
        Error,
        Receiver<HasReplyableError>,
        Self,
    > {
        match self.state.original.check_broadcast_suitability(min_fee_rate, can_broadcast) {
            Ok(()) => MaybeFatalTransition::success(
                SessionEvent::CheckedBroadcastSuitability(),
                Receiver {
                    state: MaybeInputsOwned { original: self.original.clone() },
                    session_context: self.session_context,
                },
            ),
            Err(Error::Implementation(e)) =>
                MaybeFatalTransition::transient(Error::Implementation(e), self),
            Err(e) => MaybeFatalTransition::replyable_error(
                SessionEvent::GotReplyableError((&e).into()),
                Receiver {
                    state: HasReplyableError { error_reply: (&e).into(), fallback_tx: None },
                    session_context: self.session_context,
                },
                e,
            ),
        }
    }

    /// Skip the current typestate's validations.
    ///
    /// Use this for interactive receivers, which manually create Payjoin URIs and so
    /// are not exposed to the probing attacks the checks guard against.
    ///
    /// Returns a [`NextStateTransition`] that, once successfully persisted, yields a
    /// [`Receiver<MaybeInputsOwned>`].
    pub fn assume_interactive_receiver(
        self,
    ) -> NextStateTransition<SessionEvent, Receiver<MaybeInputsOwned>> {
        NextStateTransition::success(
            SessionEvent::CheckedBroadcastSuitability(),
            Receiver {
                state: MaybeInputsOwned { original: self.original.clone() },
                session_context: self.session_context,
            },
        )
    }

    pub(crate) fn apply_checked_broadcast_suitability(self) -> ReceiveSession {
        let new_state = Receiver {
            state: MaybeInputsOwned { original: self.original.clone() },
            session_context: self.session_context,
        };
        ReceiveSession::MaybeInputsOwned(new_state)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MaybeInputsOwned {
    original: OriginalPayload,
}

/// Typestate to check that the Original PSBT has no inputs owned by the receiver.
///
/// At this point, the Original PSBT has been verified as broadcastable; the receiver
/// can call [`Receiver<MaybeInputsOwned>::extract_tx_to_schedule_broadcast`] to
/// schedule a fallback broadcast in case the payjoin fails.
///
/// Call [`Receiver<MaybeInputsOwned>::check_inputs_not_owned`] to advance to
/// [`Receiver<MaybeInputsSeen>`] to continue validation.
impl Receiver<MaybeInputsOwned> {
    /// Extract the transaction from the Original PSBT for scheduling broadcast as a
    /// fallback in case the payjoin does not complete.
    ///
    /// Returns the extracted [`bitcoin::Transaction`].
    pub fn extract_tx_to_schedule_broadcast(&self) -> bitcoin::Transaction {
        self.state.fallback_tx()
    }

    /// Check that none of the Original PSBT's inputs belong to the receiver,
    /// preventing an attacker from spending the receiver's own inputs.
    ///
    /// Returns a [`MaybeFatalTransition`] that, once successfully persisted, yields a
    /// [`Receiver<MaybeInputsSeen>`] to continue validation.
    pub fn check_inputs_not_owned(
        self,
        is_owned: &mut impl FnMut(&Script) -> Result<bool, ImplementationError>,
    ) -> MaybeFatalTransition<
        SessionEvent,
        Receiver<MaybeInputsSeen>,
        Error,
        Receiver<HasReplyableError>,
        Self,
    > {
        match self.state.original.check_inputs_not_owned(is_owned) {
            Ok(()) => MaybeFatalTransition::success(
                SessionEvent::CheckedInputsNotOwned(),
                Receiver {
                    state: MaybeInputsSeen { original: self.original.clone() },
                    session_context: self.session_context,
                },
            ),
            Err(e) => match e {
                Error::Implementation(_) => MaybeFatalTransition::transient(e, self),
                _ => MaybeFatalTransition::replyable_error(
                    SessionEvent::GotReplyableError((&e).into()),
                    Receiver {
                        state: HasReplyableError {
                            error_reply: (&e).into(),
                            fallback_tx: Some(self.state.fallback_tx()),
                        },
                        session_context: self.session_context,
                    },
                    e,
                ),
            },
        }
    }

    pub(crate) fn apply_checked_inputs_not_owned(self) -> ReceiveSession {
        let new_state = Receiver {
            state: MaybeInputsSeen { original: self.original.clone() },
            session_context: self.session_context,
        };
        ReceiveSession::MaybeInputsSeen(new_state)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MaybeInputsSeen {
    original: OriginalPayload,
}

/// Typestate to check that the Original PSBT has no inputs the receiver has seen before.
///
/// This check prevents the following attacks:
/// 1. Probing attacks, where the sender uses the exact same proposal (or with
///    minimal change) to have the receiver reveal their UTXO set by contributing
///    to all proposals with different inputs and sending them back to the receiver.
/// 2. Re-entrant payjoin, where the sender uses the payjoin PSBT of a previous
///    payjoin as the Original PSBT of the current, new payjoin.
///
/// Call [`Receiver<MaybeInputsSeen>::check_no_inputs_seen_before`] to advance to
/// [`Receiver<OutputsUnknown>`] to continue validation.
impl Receiver<MaybeInputsSeen> {
    /// Check that none of the inputs have been seen before, preventing input
    /// probing and replay attacks (where inputs have been used in a previous
    /// payjoin attempt).
    ///
    /// Returns a [`MaybeFatalTransition`] that, once successfully persisted, yields a
    /// [`Receiver<OutputsUnknown>`] to continue validation.
    pub fn check_no_inputs_seen_before(
        self,
        is_known: &mut impl FnMut(&OutPoint) -> Result<bool, ImplementationError>,
    ) -> MaybeFatalTransition<
        SessionEvent,
        Receiver<OutputsUnknown>,
        Error,
        Receiver<HasReplyableError>,
        Self,
    > {
        match self.state.original.check_no_inputs_seen_before(is_known) {
            Ok(()) => MaybeFatalTransition::success(
                SessionEvent::CheckedNoInputsSeenBefore(),
                Receiver {
                    state: OutputsUnknown { original: self.original.clone() },
                    session_context: self.session_context,
                },
            ),
            Err(e) => match e {
                Error::Implementation(_) => MaybeFatalTransition::transient(e, self),
                _ => MaybeFatalTransition::replyable_error(
                    SessionEvent::GotReplyableError((&e).into()),
                    Receiver {
                        state: HasReplyableError {
                            error_reply: (&e).into(),
                            fallback_tx: Some(self.state.fallback_tx()),
                        },
                        session_context: self.session_context,
                    },
                    e,
                ),
            },
        }
    }

    pub(crate) fn apply_checked_no_inputs_seen_before(self) -> ReceiveSession {
        let new_state = Receiver {
            state: OutputsUnknown { original: self.original.clone() },
            session_context: self.session_context,
        };
        ReceiveSession::OutputsUnknown(new_state)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OutputsUnknown {
    original: OriginalPayload,
}

/// Typestate to check that the outputs of the Original PSBT actually pay the receiver.
///
/// The receiver should only accept Original PSBTs from the sender that actually send
/// them money. Call [`Receiver<OutputsUnknown>::identify_receiver_outputs`] to advance
/// to [`Receiver<WantsOutputs>`] to continue the proposal.
impl Receiver<OutputsUnknown> {
    /// Identify which outputs in the original transaction belong to the receiver
    /// and ensure at least one output pays the receiver.
    ///
    /// If the sender designated a receiver output for fee subtraction, that designation
    /// is cleared so the receiver does not accidentally subtract fees from their own output.
    ///
    /// Returns a [`MaybeFatalTransition`] that, once successfully persisted, yields a
    /// [`Receiver<WantsOutputs>`] to continue the proposal.
    pub fn identify_receiver_outputs(
        self,
        is_receiver_output: &mut impl FnMut(&Script) -> Result<bool, ImplementationError>,
    ) -> MaybeFatalTransition<
        SessionEvent,
        Receiver<WantsOutputs>,
        Error,
        Receiver<HasReplyableError>,
        Self,
    > {
        let fallback_tx = Some(self.state.fallback_tx());
        match self.state.original.clone().identify_receiver_outputs(is_receiver_output) {
            Ok(inner) => MaybeFatalTransition::success(
                SessionEvent::IdentifiedReceiverOutputs(inner.owned_vouts.clone()),
                Receiver { state: WantsOutputs { inner }, session_context: self.session_context },
            ),
            Err(e) => match e {
                Error::Implementation(_) => MaybeFatalTransition::transient(e, self),
                _ => MaybeFatalTransition::replyable_error(
                    SessionEvent::GotReplyableError((&e).into()),
                    Receiver {
                        state: HasReplyableError { error_reply: (&e).into(), fallback_tx },
                        session_context: self.session_context,
                    },
                    e,
                ),
            },
        }
    }

    pub(crate) fn apply_identified_receiver_outputs(
        self,
        owned_vouts: Vec<usize>,
    ) -> Result<ReceiveSession, ReplayError<ReceiveSession, SessionEvent>> {
        let output_count = self.state.original.psbt.unsigned_tx.output.len();
        if owned_vouts.is_empty() || owned_vouts.iter().any(|&vout| vout >= output_count) {
            return Err(invalid_event_payload(
                SessionEvent::IdentifiedReceiverOutputs(owned_vouts),
                format!(
                    "owned vouts must be non-empty and within the original PSBT's {output_count} outputs"
                ),
            ));
        }
        let inner = common::WantsOutputs::new(self.state.original, owned_vouts);
        let new_state =
            Receiver { state: WantsOutputs { inner }, session_context: self.session_context };
        Ok(ReceiveSession::WantsOutputs(new_state))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WantsOutputs {
    inner: common::WantsOutputs,
}

/// Typestate for a checked proposal that the receiver may add or substitute outputs to.
///
/// Beyond contributing new inputs, Payjoin lets the receiver substitute the Original
/// PSBT's outputs to preserve privacy or perform batch transfers; the receiver is not
/// limited to the address shared in the Payjoin URI. Call
/// [`Receiver<WantsOutputs>::commit_outputs`] to advance to [`Receiver<WantsInputs>`].
impl Receiver<WantsOutputs> {
    /// Returns whether output substitution is enabled for this session.
    pub fn output_substitution(&self) -> OutputSubstitution { self.inner.output_substitution() }

    /// Substitute the receiver output script with the provided script.
    ///
    /// Returns an updated [`Receiver<WantsOutputs>`] with the substituted output.
    pub fn substitute_receiver_script(
        self,
        output_script: &Script,
    ) -> Result<Self, OutputSubstitutionError> {
        let inner = self.state.inner.substitute_receiver_script(output_script)?;
        Ok(Receiver { state: WantsOutputs { inner }, session_context: self.session_context })
    }

    /// Replace all receiver outputs with the provided `replacement_outputs`, and set up
    /// the `drain_script` as the receiver-owned output whose value may be adjusted based
    /// on modifications in subsequent states.
    ///
    /// For example, when the receiver contributes an input, the drain output's value is
    /// increased by the same amount; when an output's value must be reduced to cover fees,
    /// it is taken from the drain output.
    ///
    /// Returns an updated [`Receiver<WantsOutputs>`] with the replaced outputs.
    pub fn replace_receiver_outputs(
        self,
        replacement_outputs: impl IntoIterator<Item = TxOut>,
        drain_script: &Script,
    ) -> Result<Self, OutputSubstitutionError> {
        let inner = self.state.inner.replace_receiver_outputs(replacement_outputs, drain_script)?;
        Ok(Receiver { state: WantsOutputs { inner }, session_context: self.session_context })
    }

    /// Commit the output modifications and proceed to input contribution.
    ///
    /// Returns a [`NextStateTransition`] that, once successfully persisted, yields a
    /// [`Receiver<WantsInputs>`].
    pub fn commit_outputs(self) -> NextStateTransition<SessionEvent, Receiver<WantsInputs>> {
        let inner = self.state.inner.commit_outputs();
        // change_vout, chosen by the output shuffle, can't be recomputed on replay.
        NextStateTransition::success(
            SessionEvent::CommittedOutputs {
                outputs: inner.proposal.payjoin_psbt.unsigned_tx.output.clone(),
                change_vout: inner.proposal.change_vout,
            },
            Receiver { state: WantsInputs { inner }, session_context: self.session_context },
        )
    }

    pub(crate) fn apply_committed_outputs(
        self,
        outputs: Vec<TxOut>,
        change_vout: usize,
    ) -> Result<ReceiveSession, ReplayError<ReceiveSession, SessionEvent>> {
        let output_count = outputs.len();
        if change_vout >= output_count {
            return Err(invalid_event_payload(
                SessionEvent::CommittedOutputs { outputs, change_vout },
                format!(
                    "change vout {change_vout} is out of bounds; {output_count} outputs committed"
                ),
            ));
        }
        let mut payjoin_psbt = self.state.inner.original.original_psbt.clone();
        payjoin_psbt.outputs = vec![Default::default(); outputs.len()];
        payjoin_psbt.unsigned_tx.output = outputs;
        let proposal =
            common::WorkingProposal { payjoin_psbt, change_vout, receiver_inputs: vec![] };
        let inner = common::WantsInputs { original: self.state.inner.original, proposal };
        let new_state =
            Receiver { state: WantsInputs { inner }, session_context: self.session_context };
        Ok(ReceiveSession::WantsInputs(new_state))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WantsInputs {
    inner: common::WantsInputs,
}

/// Typestate for a checked proposal that the receiver may contribute inputs to.
///
/// Optionally pick a privacy-preserving input with
/// [`Receiver<WantsInputs>::try_preserving_privacy`], add inputs with
/// [`Receiver<WantsInputs>::contribute_inputs`], then call
/// [`Receiver<WantsInputs>::commit_inputs`] to advance to [`Receiver<WantsFeeRange>`].
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
    ) -> Result<InputPair, CoinSelectionError> {
        self.inner.try_preserving_privacy(candidate_inputs)
    }

    /// Add the provided inputs to the payjoin proposal at random indices. Any input value
    /// exceeding the total output amount is added to the receiver's change output.
    ///
    /// Returns an updated [`Receiver<WantsInputs>`] with the contributed inputs.
    pub fn contribute_inputs(
        self,
        inputs: impl IntoIterator<Item = InputPair>,
    ) -> Result<Self, InputContributionError> {
        let inner = self.state.inner.contribute_inputs(inputs)?;
        Ok(Receiver { state: WantsInputs { inner }, session_context: self.session_context })
    }

    /// Commit the input contributions and proceed to fee negotiation.
    ///
    /// Returns a [`NextStateTransition`] that, once successfully persisted, yields a
    /// [`Receiver<WantsFeeRange>`].
    pub fn commit_inputs(self) -> NextStateTransition<SessionEvent, Receiver<WantsFeeRange>> {
        let inner = self.state.inner.commit_inputs();
        // The RNG insert order and change bump aren't reconstructable; store the PSBT.
        NextStateTransition::success(
            SessionEvent::CommittedInputs {
                receiver_inputs: inner.proposal.receiver_inputs.clone(),
                payjoin_psbt: inner.proposal.payjoin_psbt.clone(),
            },
            Receiver { state: WantsFeeRange { inner }, session_context: self.session_context },
        )
    }

    pub(crate) fn apply_committed_inputs(
        self,
        receiver_inputs: Vec<InputPair>,
        payjoin_psbt: Psbt,
    ) -> Result<ReceiveSession, ReplayError<ReceiveSession, SessionEvent>> {
        // change_vout is unchanged by contribute_inputs; recover it from the predecessor.
        let change_vout = self.state.inner.proposal.change_vout;
        let output_count = payjoin_psbt.unsigned_tx.output.len();
        if change_vout >= output_count {
            return Err(invalid_event_payload(
                SessionEvent::CommittedInputs { receiver_inputs, payjoin_psbt },
                format!(
                    "change vout {change_vout} is out of bounds; committed PSBT has {output_count} outputs"
                ),
            ));
        }
        let proposal = common::WorkingProposal { payjoin_psbt, change_vout, receiver_inputs };
        let inner = common::WantsFeeRange { original: self.state.inner.original, proposal };
        let new_state =
            Receiver { state: WantsFeeRange { inner }, session_context: self.session_context };
        Ok(ReceiveSession::WantsFeeRange(new_state))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct WantsFeeRange {
    inner: common::WantsFeeRange,
}

/// Typestate for a checked proposal that applies additional fee contribution for the
/// receiver contributed inputs and outputs.
///
/// Call [`Receiver<WantsFeeRange>::apply_fee_range`] to advance to
/// [`Receiver<ProvisionalProposal>`].
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
    ///
    /// Returns a [`MaybeFatalTransition`] that, once successfully persisted, yields a
    /// [`Receiver<ProvisionalProposal>`].
    pub fn apply_fee_range(
        self,
        min_fee_rate: Option<FeeRate>,
        max_effective_fee_rate: Option<FeeRate>,
    ) -> MaybeFatalTransition<SessionEvent, Receiver<ProvisionalProposal>, ProtocolError, (), Self>
    {
        let max_effective_fee_rate =
            max_effective_fee_rate.or(Some(self.session_context.max_fee_rate));
        match self
            .state
            .inner
            .clone()
            .calculate_psbt_context_with_fee_range(min_fee_rate, max_effective_fee_rate)
        {
            Ok(psbt_context) => MaybeFatalTransition::success(
                SessionEvent::AppliedFeeRange(psbt_context.clone()),
                Receiver {
                    state: ProvisionalProposal { psbt_context },
                    session_context: self.session_context,
                },
            ),
            Err(e) =>
                MaybeFatalTransition::transient(ProtocolError::OriginalPayload(e.into()), self),
        }
    }

    pub(crate) fn apply_applied_fee_range(self, psbt_context: PsbtContext) -> ReceiveSession {
        let new_state = Receiver {
            state: ProvisionalProposal { psbt_context },
            session_context: self.session_context,
        };
        ReceiveSession::ProvisionalProposal(new_state)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProvisionalProposal {
    psbt_context: PsbtContext,
}

/// Typestate for a checked proposal that the receiver has modified the outputs and
/// inputs of, and is ready to be signed and finalized.
///
/// Call [`Receiver<ProvisionalProposal>::finalize_proposal`] to advance to
/// [`Receiver<PayjoinProposal>`].
impl Receiver<ProvisionalProposal> {
    /// Finalize the proposal by signing the PSBT via the `wallet_process_psbt` callback.
    ///
    /// Returns a [`MaybeTransientTransition`] that, once successfully persisted, yields the
    /// final [`Receiver<PayjoinProposal>`].
    pub fn finalize_proposal(
        self,
        wallet_process_psbt: impl Fn(&Psbt) -> Result<Psbt, ImplementationError>,
    ) -> MaybeTransientTransition<SessionEvent, Receiver<PayjoinProposal>, ImplementationError, Self>
    {
        let payjoin_psbt =
            match self.state.psbt_context.clone().finalize_proposal(wallet_process_psbt) {
                Ok(payjoin_psbt) => payjoin_psbt,
                Err(e) => {
                    return MaybeTransientTransition::transient(e, self);
                }
            };
        let psbt_context = PsbtContext {
            payjoin_psbt: payjoin_psbt.clone(),
            original_psbt: self.state.psbt_context.original_psbt,
        };
        let payjoin_proposal = PayjoinProposal { psbt_context: psbt_context.clone() };
        MaybeTransientTransition::success(
            SessionEvent::FinalizedProposal(payjoin_psbt),
            Receiver { state: payjoin_proposal, session_context: self.session_context },
        )
    }

    /// Extract the PSBT that needs to be signed by the receiver's wallet.
    ///
    /// In some applications the entity that progresses the typestate is different from the
    /// entity that has access to the private keys, so the PSBT to sign must be accessible to
    /// such implementers.
    ///
    /// Returns the Payjoin proposal [`Psbt`] to be signed.
    pub fn psbt_to_sign(&self) -> Psbt { self.state.psbt_context.psbt_to_sign() }

    pub(crate) fn apply_payjoin_proposal(self, payjoin_psbt: Psbt) -> ReceiveSession {
        let psbt_context = PsbtContext {
            payjoin_psbt,
            original_psbt: self.state.psbt_context.original_psbt.clone(),
        };
        let new_state = Receiver {
            state: PayjoinProposal { psbt_context },
            session_context: self.session_context,
        };
        ReceiveSession::PayjoinProposal(new_state)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PayjoinProposal {
    psbt_context: PsbtContext,
}

/// Typestate for a signed and finalized Payjoin proposal that is to be sent to the
/// sender for them to sign and broadcast.
///
/// Post the proposal to the Payjoin directory with
/// [`Receiver<PayjoinProposal>::create_post_request`], then submit the Payjoin directory
/// response to [`Receiver<PayjoinProposal>::process_response`] to advance to
/// [`Receiver<Monitor>`].
impl Receiver<PayjoinProposal> {
    /// Returns the finalized payjoin proposal PSBT.
    pub fn psbt(&self) -> &Psbt { &self.psbt_context.payjoin_psbt }

    /// Construct an OHTTP-encapsulated HTTP request carrying the Proposal PSBT.
    ///
    /// The inner HTTP method, body encoding, and target mailbox depend on
    /// whether the original sender used Payjoin v2 (BIP 77) or Payjoin v1
    /// (BIP 78), as recorded in the session context:
    ///
    /// - v2 sender (reply key present): POST an HPKE-encrypted `PjV2MsgB`
    ///   payload to the sender's reply mailbox.
    /// - v1 sender (no reply key): PUT the base64-encoded PSBT as cleartext
    ///   UTF-8 bytes to the receiver's own mailbox, per the
    ///   [BIP 77](https://github.com/bitcoin/bips/blob/master/bip-0077.md)
    ///   Backwards compatibility section.
    ///
    /// Both paths are then OHTTP-encapsulated to the directory's OHTTP Gateway.
    pub fn create_post_request(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, OhttpResponse), CreateRequestError> {
        if self.session_context.expiration.elapsed() {
            return Err(InternalCreateRequestError::Expired(self.session_context.expiration).into());
        }

        let target_resource: Url;
        let body: Vec<u8>;
        let method: &str;

        if let Some(e) = &self.session_context.reply_key {
            // Prepare v2 payload
            let payjoin_bytes = self.psbt().serialize();
            let sender_mailbox = short_id_from_pubkey(e);
            target_resource = mailbox_endpoint(&self.session_context.directory, &sender_mailbox);
            body = encrypt_message_b(payjoin_bytes, &self.session_context.receiver_key, e)?;
            method = "POST";
        } else {
            // Prepare v2 wrapped and backwards-compatible v1 payload
            body = self.psbt().to_string().as_bytes().to_vec();
            let receiver_mailbox = self.session_context.proposal_mailbox_id();
            target_resource = mailbox_endpoint(&self.session_context.directory, &receiver_mailbox);
            method = "PUT";
        }
        tracing::trace!("Payjoin PSBT target: {}", target_resource.as_str());
        let (body, ctx) = ohttp_encapsulate(
            &self.session_context.ohttp_keys,
            method,
            target_resource.as_str(),
            Some(&body),
        )?;

        let req = Request::new_v2(&self.session_context.full_relay_url(ohttp_relay)?, &body);
        Ok((req, OhttpResponse::new(ctx)))
    }

    /// Process the Payjoin directory response to the posted Payjoin proposal.
    ///
    /// Returns a [`MaybeFatalTransition`] that, once successfully persisted, yields a
    /// [`Receiver<Monitor>`] to watch for the payjoin transaction.
    pub fn process_response(
        self,
        res: &[u8],
        ohttp_context: OhttpResponse,
    ) -> MaybeFatalTransition<
        SessionEvent,
        Receiver<Monitor>,
        ProtocolError,
        Receiver<PendingFallback>,
        Self,
    > {
        match process_post_res(res, ohttp_context.into_inner()) {
            Ok(_) => MaybeFatalTransition::success(
                SessionEvent::PostedPayjoinProposal(),
                Receiver {
                    state: Monitor { psbt_context: self.state.psbt_context.clone() },
                    session_context: self.session_context.clone(),
                },
            ),
            Err(e) =>
                if e.is_fatal() {
                    MaybeFatalTransition::replyable_error(
                        SessionEvent::ProtocolFailed,
                        Receiver {
                            state: PendingFallback { fallback_tx: self.state.fallback_tx() },
                            session_context: self.session_context.clone(),
                        },
                        ProtocolError::V2(InternalSessionError::DirectoryResponse(e).into()),
                    )
                } else {
                    MaybeFatalTransition::transient(
                        ProtocolError::V2(InternalSessionError::DirectoryResponse(e).into()),
                        self,
                    )
                },
        }
    }

    pub(crate) fn apply_payjoin_posted(self) -> ReceiveSession {
        ReceiveSession::Monitor(Receiver {
            state: Monitor { psbt_context: self.state.psbt_context.clone() },
            session_context: self.session_context,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HasReplyableError {
    error_reply: JsonReply,
    fallback_tx: Option<bitcoin::Transaction>,
}

/// Typestate for a receiver that hit a replyable error during validation.
///
/// Post the error to the Payjoin directory to communicate it to the sender with
/// [`Receiver<HasReplyableError>::create_error_request`], then submit the Payjoin
/// directory response to [`Receiver<HasReplyableError>::process_error_response`].
/// Alternatively, call [`Receiver<HasReplyableError>::cancel`] to skip posting the error.
impl Receiver<HasReplyableError> {
    /// Cancel the Payjoin session without posting the replyable error to the Payjoin directory.
    ///
    /// Returns a [`MaybeTerminalTransition`] that, once successfully persisted, yields a
    /// [`Receiver<PendingFallback>`] if the session has a validated fallback transaction,
    /// or otherwise closes the session.
    pub fn cancel(self) -> MaybeTerminalTransition<SessionEvent, Receiver<PendingFallback>> {
        let Receiver { state: HasReplyableError { fallback_tx, .. }, session_context } = self;
        match fallback_tx {
            Some(fallback_tx) => MaybeTerminalTransition::advance(
                SessionEvent::Cancelled,
                Receiver { state: PendingFallback { fallback_tx }, session_context },
            ),
            None =>
                MaybeTerminalTransition::terminate(SessionEvent::Closed(SessionOutcome::Aborted)),
        }
    }

    /// Construct an OHTTP encapsulated POST request to post the replyable error to the
    /// Payjoin directory so it can be retrieved by the sender.
    pub fn create_error_request(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, OhttpResponse), CreateRequestError> {
        let session_context = &self.session_context;
        if session_context.expiration.elapsed() {
            return Err(InternalCreateRequestError::Expired(self.session_context.expiration).into());
        }
        let mailbox =
            mailbox_endpoint(&session_context.directory, &session_context.reply_mailbox_id());
        let body = {
            if let Some(reply_key) = &session_context.reply_key {
                encrypt_message_b(
                    self.error_reply.to_json().to_string().into_bytes(),
                    &session_context.receiver_key,
                    reply_key,
                )?
            } else {
                // Post a generic unavailable error message in the case where we don't have a reply key
                let err =
                    JsonReply::new(crate::error_codes::ErrorCode::Unavailable, "Receiver error");
                err.to_json().to_string().as_bytes().to_vec()
            }
        };
        let (body, ohttp_ctx) =
            ohttp_encapsulate(&session_context.ohttp_keys, "POST", mailbox.as_str(), Some(&body))
                .map_err(InternalCreateRequestError::OhttpEncapsulation)?;
        let req = Request::new_v2(&session_context.full_relay_url(ohttp_relay)?, &body);
        Ok((req, OhttpResponse::new(ohttp_ctx)))
    }

    /// Process the Payjoin directory response to the posted replyable error.
    ///
    /// Returns a [`MaybeTerminalSuccessTransition`] that, once successfully persisted,
    /// completes the error reporting and yields a [`Receiver<PendingFallback>`] if the
    /// session has a validated fallback transaction, or otherwise closes the session.
    pub fn process_error_response(
        self,
        res: &[u8],
        ohttp_context: OhttpResponse,
    ) -> MaybeTerminalSuccessTransition<SessionEvent, Receiver<PendingFallback>, ProtocolError, Self>
    {
        let pending = self.pending_fallback_after_protocol_failure();
        let event = match &pending {
            Some(_) => SessionEvent::ProtocolFailed,
            None => SessionEvent::Closed(SessionOutcome::Aborted),
        };
        let protocol_error =
            |e| ProtocolError::V2(InternalSessionError::DirectoryResponse(e).into());

        match (process_post_res(res, ohttp_context.into_inner()), pending) {
            (Ok(_), Some(pending_fallback)) =>
                MaybeTerminalSuccessTransition::advance(event, pending_fallback),
            (Ok(_), None) => MaybeTerminalSuccessTransition::terminate(event),
            (Err(e), _) if !e.is_fatal() =>
                MaybeTerminalSuccessTransition::transient(protocol_error(e), self),
            (Err(e), Some(pending_fallback)) => MaybeTerminalSuccessTransition::fatal_advance(
                event,
                pending_fallback,
                protocol_error(e),
            ),
            (Err(e), None) =>
                MaybeTerminalSuccessTransition::fatal_terminate(event, protocol_error(e)),
        }
    }

    fn pending_fallback_after_protocol_failure(&self) -> Option<Receiver<PendingFallback>> {
        self.state.fallback_tx.clone().map(|fallback_tx| Receiver {
            state: PendingFallback { fallback_tx },
            session_context: self.session_context.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Monitor {
    psbt_context: PsbtContext,
}

/// Typestate to monitor the network for the Payjoin proposal or fallback transaction.
///
/// After the Payjoin proposal is signed and sent back to the sender, the receiver should monitor
/// the network and confirm the status of transaction (or the fallback). In this case, the status
/// can refer to whether the transaction has been broadcast, has some number of confirmations, etc.
/// The caller should decide the condition that must be satisfied for the Payjoin to be considered
/// successful.
///
/// Call [`Receiver<Monitor>::check_for_transaction`] to confirm the status of the transaction in the
/// network and conclude the Payjoin session.
impl Receiver<Monitor> {
    /// Check the network for the payjoin or fallback transaction via the `find_transaction`
    /// callback.
    ///
    /// Returns a [`MaybeFatalOrSuccessTransition`] that, once successfully persisted, either
    /// concludes the session if a transaction is found, or yields a [`Receiver<Monitor>`] to
    /// remain in stasis if no transaction is found yet.
    pub fn check_for_transaction(
        self,
        find_transaction: impl Fn(Txid) -> Result<Option<bitcoin::Transaction>, ImplementationError>,
    ) -> MaybeFatalOrSuccessTransition<SessionEvent, Self, Error> {
        let fallback_tx = self.state.fallback_tx();

        // If the fallback transaction included any non-SegWit inputs, then the transaction ID of
        // the Payjoin proposal is going to change when the sender signs their non-SegWit address
        // one more time. The receiver cannot monitor the transaction, and should conclude the session.
        if !self.proposal_txid_is_stable() {
            return MaybeFatalOrSuccessTransition::success(SessionEvent::Closed(
                SessionOutcome::PayjoinProposalSent,
            ));
        }

        let payjoin_proposal = &self.state.psbt_context.payjoin_psbt;
        let payjoin_txid = payjoin_proposal.unsigned_tx.compute_txid();
        // If the sender is spending SegWit-only inputs, then the transaction ID of the Payjoin proposal
        // is not going to change when the sender signs it. So we can use the TXID to check the
        // network for the Payjoin proposal.
        match find_transaction(payjoin_txid) {
            Ok(Some(tx)) => {
                let tx_id = tx.compute_txid();
                if tx_id != payjoin_txid {
                    return MaybeFatalOrSuccessTransition::transient(
                        Error::Implementation(ImplementationError::from(
                            format!("Payjoin transaction ID mismatch. Expected: {payjoin_txid}, Got: {tx_id}").as_str(),
                        )),
                        self,
                    );
                }
                // Payjoin transaction with SegWit inputs was detected. Complete the session,
                // recording the txid of the transaction that settled it.
                return MaybeFatalOrSuccessTransition::success(SessionEvent::Closed(
                    SessionOutcome::Success(tx_id),
                ));
            }
            Ok(None) => {}
            Err(e) =>
                return MaybeFatalOrSuccessTransition::transient(Error::Implementation(e), self),
        }

        // If the Payjoin proposal was not found, check the fallback transaction, as it is
        // the second of two transactions whose IDs the receiver is aware of.
        match find_transaction(fallback_tx.compute_txid()) {
            Ok(Some(_)) =>
                return MaybeFatalOrSuccessTransition::success(SessionEvent::Closed(
                    SessionOutcome::FallbackBroadcasted,
                )),
            Ok(None) => {}
            Err(e) =>
                return MaybeFatalOrSuccessTransition::transient(Error::Implementation(e), self),
        }

        MaybeFatalOrSuccessTransition::no_results(self)
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
pub(crate) fn pj_uri(
    session_context: &SessionContext,
    output_substitution: OutputSubstitution,
) -> crate::PjUri {
    use crate::uri::PayjoinExtras;
    let pj_param = crate::uri::PjParam::V2(crate::uri::v2::PjParam::new(
        session_context.directory.clone(),
        session_context.proposal_mailbox_id(),
        session_context.expiration,
        session_context.ohttp_keys.clone(),
        session_context.receiver_key.public_key().clone(),
    ));
    let extras = PayjoinExtras { pj_param, output_substitution };
    let mut uri = crate::uri::PjUri::from_extras(session_context.address.clone(), extras);
    if let Some(amount) = session_context.amount {
        uri.set_amount(amount);
    }

    uri
}

#[cfg(test)]
pub mod test {
    use std::str::FromStr;

    use bitcoin::{Amount, FeeRate, ScriptBuf, Witness};
    use once_cell::sync::Lazy;
    use payjoin_test_utils::{
        BoxError, EXAMPLE_URL, ORIGINAL_PSBT, PARSED_ORIGINAL_PSBT, PARSED_PAYJOIN_PROPOSAL,
        QUERY_PARAMS,
    };

    use super::*;
    use crate::output_substitution::OutputSubstitution;
    use crate::persist::{
        InMemoryPersister, OptionalTransitionOutcome, RejectTransient, Rejection, SessionPersister,
    };
    use crate::receive::optional_parameters::Params;
    use crate::receive::v2;
    use crate::ImplementationError;

    pub(crate) static SHARED_CONTEXT: Lazy<SessionContext> = Lazy::new(|| SessionContext {
        address: Address::from_str("tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4")
            .expect("valid address")
            .assume_checked(),
        directory: Url::from_str(EXAMPLE_URL).expect("Could not parse Url"),
        ohttp_keys: OhttpKeys::decode(&payjoin_test_utils::ohttp_key_config_bytes())
            .expect("valid ohttp keys"),
        expiration: Time::from_now(Duration::from_secs(60)).expect("Valid timestamp"),
        receiver_key: HpkeKeyPair::gen_keypair(),
        reply_key: None,
        amount: None,
        max_fee_rate: FeeRate::BROADCAST_MIN,
    });

    pub(crate) fn unchecked_proposal_v2_from_test_vector() -> UncheckedOriginalPayload {
        let params = Params::from_query_str(QUERY_PARAMS, &[Version::Two])
            .expect("Test utils query params should not fail");
        UncheckedOriginalPayload {
            original: OriginalPayload { psbt: PARSED_ORIGINAL_PSBT.clone(), params },
        }
    }

    pub(crate) fn maybe_inputs_owned_v2_from_test_vector() -> MaybeInputsOwned {
        let params = Params::from_query_str(QUERY_PARAMS, &[Version::Two])
            .expect("Test utils query params should not fail");
        MaybeInputsOwned {
            original: OriginalPayload { psbt: PARSED_ORIGINAL_PSBT.clone(), params },
        }
    }

    pub(crate) fn mock_err() -> JsonReply {
        let persister = InMemoryPersister::default();
        let receiver = Receiver {
            state: unchecked_proposal_v2_from_test_vector(),
            session_context: SHARED_CONTEXT.clone(),
        };
        let error = receiver
            .clone()
            .check_broadcast_suitability(None, |_| Err("mock error".into()))
            .save(&persister)
            .expect_err("Server error should be populated with mock error");
        let res = error.api_error().expect("check_broadcast error should propagate to api error");
        JsonReply::from(&res)
    }

    pub(crate) fn mock_fallback_tx() -> bitcoin::Transaction {
        PARSED_ORIGINAL_PSBT.clone().extract_tx_unchecked_fee_rate()
    }

    fn receiver<S>(state: S) -> Receiver<S> {
        Receiver { state, session_context: SHARED_CONTEXT.clone() }
    }

    fn assert_events(
        persister: &InMemoryPersister<SessionEvent>,
        expected_events: &[SessionEvent],
        expected_closed: bool,
    ) {
        let inner = persister.inner.lock().expect("Shouldn't be poisoned");
        assert_eq!(&*inner.events, expected_events);
        assert_eq!(inner.is_closed, expected_closed);
    }

    fn ohttp_response_for(req_body: &[u8], status: http::StatusCode) -> Vec<u8> {
        let server = payjoin_test_utils::ohttp_server();
        let (_, probe_response) = server.decapsulate(req_body).expect("request should decapsulate");
        let response_overhead =
            probe_response.encapsulate(&[]).expect("probe should encrypt").len();

        let (_, server_response) =
            server.decapsulate(req_body).expect("request should decapsulate again");
        let mut bhttp_response =
            vec![0u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES - response_overhead];
        bhttp::Message::response(
            bhttp::StatusCode::try_from(status.as_u16()).expect("status should be valid"),
        )
        .write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_response.as_mut_slice())
        .expect("BHTTP response should encode");
        let encrypted =
            server_response.encapsulate(&bhttp_response).expect("response should encrypt");
        assert_eq!(encrypted.len(), crate::directory::ENCAPSULATED_MESSAGE_BYTES);
        encrypted
    }

    /// Build a native SegWit (P2WPKH) original/payjoin PSBT pair for tests
    /// that need a txid-stable sender input.
    ///
    /// The canonical BIP78 vectors cannot serve that purpose: their sender
    /// input is P2SH-wrapped SegWit, so the finalized input carries the
    /// redeem script push in its script_sig, which changes the transaction
    /// ID when the sender signs.
    fn native_segwit_psbt_context() -> PsbtContext {
        use bitcoin::hashes::Hash;

        let payment_spk = SHARED_CONTEXT.address.script_pubkey();
        let sender_outpoint =
            bitcoin::OutPoint { txid: bitcoin::Txid::from_byte_array([0x11; 32]), vout: 0 };
        let receiver_outpoint =
            bitcoin::OutPoint { txid: bitcoin::Txid::from_byte_array([0x22; 32]), vout: 1 };
        let sender_utxo = bitcoin::TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
                [0x33; 20],
            )),
        };
        let receiver_utxo = bitcoin::TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array(
                [0x44; 20],
            )),
        };
        let txin_for = |previous_output| bitcoin::TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        };
        let mut dummy_witness = Witness::new();
        dummy_witness.push([0x30; 71]); // dummy signature
        dummy_witness.push([0x02; 33]); // dummy compressed pubkey

        let original_unsigned_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![txin_for(sender_outpoint)],
            output: vec![bitcoin::TxOut {
                value: Amount::from_sat(99_000),
                script_pubkey: payment_spk.clone(),
            }],
        };
        let mut original_psbt =
            Psbt::from_unsigned_tx(original_unsigned_tx).expect("known tx should convert");
        original_psbt.inputs[0].witness_utxo = Some(sender_utxo.clone());
        original_psbt.inputs[0].final_script_witness = Some(dummy_witness);

        let payjoin_unsigned_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![txin_for(sender_outpoint), txin_for(receiver_outpoint)],
            output: vec![bitcoin::TxOut {
                value: Amount::from_sat(148_000),
                script_pubkey: payment_spk,
            }],
        };
        let mut payjoin_psbt =
            Psbt::from_unsigned_tx(payjoin_unsigned_tx).expect("known tx should convert");
        payjoin_psbt.inputs[0].witness_utxo = Some(sender_utxo);
        payjoin_psbt.inputs[1].witness_utxo = Some(receiver_utxo);

        PsbtContext { original_psbt, payjoin_psbt }
    }

    #[test]
    fn test_monitor_typestate() -> Result<(), BoxError> {
        let psbt_ctx = native_segwit_psbt_context();
        let payjoin_tx = psbt_ctx.payjoin_psbt.unsigned_tx.clone();
        let original_tx = psbt_ctx.original_psbt.clone().extract_tx().expect("valid tx");
        let monitor = Receiver {
            state: Monitor { psbt_context: psbt_ctx },
            session_context: SHARED_CONTEXT.clone(),
        };

        // The sender's input is native SegWit — its script_sig stays empty when
        // finalized — so the proposal's transaction ID is monitorable.
        assert!(monitor.proposal_txid_is_stable());

        // Nothing was spent, should be in the same state
        let persister = InMemoryPersister::default();
        let res = monitor
            .clone()
            .check_for_transaction(|_| Ok(None))
            .save(&persister)
            .expect("InMemoryPersister shouldn't fail");
        assert!(matches!(res, OptionalTransitionOutcome::Stasis(_)));
        assert!(!persister.inner.lock().expect("Shouldn't be poisoned").is_closed);
        assert_eq!(persister.inner.lock().expect("Shouldn't be poisoned").events.len(), 0);

        // Payjoin was broadcasted, should progress to success
        let persister = InMemoryPersister::default();
        let res = monitor
            .clone()
            .check_for_transaction(|_| Ok(Some(payjoin_tx.clone())))
            .save(&persister)
            .expect("InMemoryPersister shouldn't fail");

        assert!(matches!(res, OptionalTransitionOutcome::Progress(_)));
        assert!(persister.inner.lock().expect("Shouldn't be poisoned").is_closed);
        assert_eq!(persister.inner.lock().expect("Shouldn't be poisoned").events.len(), 1);
        assert_eq!(
            persister.inner.lock().expect("Shouldn't be poisoned").events.last(),
            Some(&SessionEvent::Closed(SessionOutcome::Success(payjoin_tx.compute_txid())))
        );

        // Fallback was broadcasted, should progress to success
        let persister = InMemoryPersister::default();
        let res = monitor
            .check_for_transaction(|txid| {
                // Emulate if one of the fallback outpoints was double spent
                if txid == original_tx.compute_txid() {
                    Ok(Some(original_tx.clone()))
                } else {
                    Ok(None)
                }
            })
            .save(&persister)
            .expect("InMemoryPersister shouldn't fail");

        assert!(matches!(res, OptionalTransitionOutcome::Progress(_)));
        assert!(persister.inner.lock().expect("Shouldn't be poisoned").is_closed);
        assert_eq!(persister.inner.lock().expect("Shouldn't be poisoned").events.len(), 1);
        assert_eq!(
            persister.inner.lock().expect("Shouldn't be poisoned").events.last(),
            Some(&SessionEvent::Closed(SessionOutcome::FallbackBroadcasted))
        );

        // Fallback transaction is non-SegWit address type, should end the session without checking
        // the network for broadcasts.
        // Not using the test-utils vectors here as they are SegWit.
        let parsed_original_psbt_p2pkh = Psbt::from_str("cHNidP8BAFICAAAAAd5tU7sqAGa46oUVdEfV1HTeVVPYqvSvxy8/dvF3dwpZAQAAAAD9////AUTxBSoBAAAAFgAUhV1NWa6seBB5g6VZC2lnduxfEaUAAAAAAAEA/QoBAgAAAAIT2eO393FPqJ4fw6NH0rXALebtTCderecX0y6DumtjNgAAAAAA/f///5hrwcRiTXqXScbvk3APDdzy162Yj+6JD/iSEO9KYQl+AQAAAGpHMEQCIGcFm57xH5tQvJMipWfzxS7OGRi7+JfTT6WA27kOt8fVAiAp2I3WGdLk3/dVhoVxN6Jl9Wp/xeCIZZ1OTukSs8jszgEhAjjEq9kNnhvQbdVlWsE9QTIe4h39UPQ8flvU5Ivq6DFm/f///wIo3gUqAQAAABl2qRTWng6zTFWPZX1k12UqqBI6kLz8z4isAPIFKgEAAAAZdqkUIz2wzl605b3cg3j72nXReQuXXaWIrGcAAAABB2pHMEQCIEP33+9X/ecNmaiydM54HS+HoHfZygAQ/vMlc5r1IWkeAiA9oKjOVmp+RnrDF4zzHHGtoG1yy1+UWXBNaDiwd0LokgEhAmfCwbIv1mi5psiB3HFqXN1bFAo+goNUPWIso60J1matAAA=").expect("known psbt should parse");
        let parsed_payjoin_proposal_p2pkh: Psbt =
            Psbt::from_str("cHNidP8BAHsCAAAAAphrwcRiTXqXScbvk3APDdzy162Yj+6JD/iSEO9KYQl+AAAAAAD9////3m1TuyoAZrjqhRV0R9XUdN5VU9iq9K/HLz928Xd3ClkBAAAAAP3///8BsOILVAIAAAAWABSFXU1Zrqx4EHmDpVkLaWd27F8RpQAAAAAAAQCgAgAAAAJgEjBIihNzFXar4wIYepzXJwQVpbqZep9GCY8pQCqh3wAAAAAA/f///x8caN/onT7AOPRWJz7vnT6yiNxcsAIs/U3RcgU4kiq4AAAAAAD9////AgDyBSoBAAAAGXapFDGh2kOIa5aNVHT2bHSoFfcawEMiiKyk6QUqAQAAABl2qRQY8AsQvx+jg9NdGUwCuShS3qk2KYisZwAAAAEBIgDyBSoBAAAAGXapFDGh2kOIa5aNVHT2bHSoFfcawEMiiKwBB2pHMEQCICQEE2dMDzlyH3ojsc0l98Da0yd2ARuy5AcWQjlgHHjkAiA70WPB+yQhW5zhsOBTg6qLsi0KzoofRAj1BZFpKT2QwAEhA68L99Q+xdIIp0rinuVDs+4qmqMZwg4E+aqbTQ8RClXLAAEA/QoBAgAAAAIT2eO393FPqJ4fw6NH0rXALebtTCderecX0y6DumtjNgAAAAAA/f///5hrwcRiTXqXScbvk3APDdzy162Yj+6JD/iSEO9KYQl+AQAAAGpHMEQCIGcFm57xH5tQvJMipWfzxS7OGRi7+JfTT6WA27kOt8fVAiAp2I3WGdLk3/dVhoVxN6Jl9Wp/xeCIZZ1OTukSs8jszgEhAjjEq9kNnhvQbdVlWsE9QTIe4h39UPQ8flvU5Ivq6DFm/f///wIo3gUqAQAAABl2qRTWng6zTFWPZX1k12UqqBI6kLz8z4isAPIFKgEAAAAZdqkUIz2wzl605b3cg3j72nXReQuXXaWIrGcAAAAAAA==").expect("known psbt should parse");

        let psbt_ctx_p2pkh = PsbtContext {
            original_psbt: parsed_original_psbt_p2pkh.clone(),
            payjoin_psbt: parsed_payjoin_proposal_p2pkh.clone(),
        };
        let monitor = Receiver {
            state: Monitor { psbt_context: psbt_ctx_p2pkh },
            session_context: SHARED_CONTEXT.clone(),
        };

        // A non-SegWit sender input means the sender's final signature will change
        // the proposal's transaction ID.
        assert!(!monitor.proposal_txid_is_stable());

        let persister = InMemoryPersister::default();
        let res = monitor
            .check_for_transaction(|_| {
                panic!("check_for_transaction should return before this closure is called")
            })
            .save(&persister)
            .expect("InMemoryPersister shouldn't fail");

        assert!(matches!(res, OptionalTransitionOutcome::Progress(_)));
        assert!(persister.inner.lock().expect("Shouldn't be poisoned").is_closed);
        assert_eq!(persister.inner.lock().expect("Shouldn't be poisoned").events.len(), 1);
        assert_eq!(
            persister.inner.lock().expect("Shouldn't be poisoned").events.last(),
            Some(&SessionEvent::Closed(SessionOutcome::PayjoinProposalSent))
        );

        Ok(())
    }

    #[test]
    fn test_nested_segwit_sender_input_txid_is_unstable() -> Result<(), BoxError> {
        use bitcoin::hashes::Hash;

        // P2SH-wrapped SegWit (e.g. P2SH-P2WPKH): the finalized input carries
        // a non-empty witness AND a script_sig holding the redeem script push.
        // The script_sig is part of the txid preimage, so the txid computed
        // from the unsigned proposal never appears on the network even though
        // the witness is non-empty.
        let unsigned_original_tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: PARSED_ORIGINAL_PSBT.unsigned_tx.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::default(),
            }],
            output: vec![bitcoin::TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: SHARED_CONTEXT.address.script_pubkey(),
            }],
        };
        let mut original_psbt = Psbt::from_unsigned_tx(unsigned_original_tx)?;
        let redeem_script =
            ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([0x88; 20]));
        original_psbt.inputs[0].final_script_sig = Some(
            bitcoin::script::Builder::new()
                .push_slice(
                    <&bitcoin::script::PushBytes>::try_from(redeem_script.as_bytes())
                        .expect("redeem script fits in a push"),
                )
                .into_script(),
        );
        let mut witness = Witness::new();
        witness.push([0x30; 71]); // dummy signature
        witness.push([0x02; 33]); // dummy compressed pubkey
        original_psbt.inputs[0].final_script_witness = Some(witness);

        // Ground truth: finalizing the nested SegWit input rewrites the
        // script_sig and therefore changes the transaction ID.
        assert_ne!(
            original_psbt.unsigned_tx.compute_txid(),
            original_psbt.clone().extract_tx_unchecked_fee_rate().compute_txid(),
            "nested SegWit finalization must change the txid",
        );

        let monitor = Receiver {
            state: Monitor {
                psbt_context: PsbtContext {
                    original_psbt,
                    payjoin_psbt: PARSED_PAYJOIN_PROPOSAL.clone(),
                },
            },
            session_context: SHARED_CONTEXT.clone(),
        };

        // A nested SegWit sender input means the sender's final script_sig
        // (the redeem script push) will change the proposal's transaction ID,
        // even though the input also has a witness.
        assert!(!monitor.proposal_txid_is_stable());

        // check_for_transaction must conclude the session without polling
        // for a transaction ID that will never appear.
        let persister = InMemoryPersister::default();
        let res = monitor
            .check_for_transaction(|_| {
                panic!("check_for_transaction should return before this closure is called")
            })
            .save(&persister)
            .expect("InMemoryPersister shouldn't fail");

        assert!(matches!(res, OptionalTransitionOutcome::Progress(_)));
        assert!(persister.inner.lock().expect("Shouldn't be poisoned").is_closed);
        assert_eq!(
            persister.inner.lock().expect("Shouldn't be poisoned").events.last(),
            Some(&SessionEvent::Closed(SessionOutcome::PayjoinProposalSent))
        );

        Ok(())
    }

    #[test]
    fn test_v2_mutable_receiver_state_closures() {
        let persister = InMemoryPersister::default();
        let mut call_count = 0;
        let maybe_inputs_owned = maybe_inputs_owned_v2_from_test_vector();
        let receiver =
            v2::Receiver { state: maybe_inputs_owned, session_context: SHARED_CONTEXT.clone() };

        fn mock_callback(call_count: &mut usize, ret: bool) -> Result<bool, ImplementationError> {
            *call_count += 1;
            Ok(ret)
        }

        let maybe_inputs_seen = receiver
            .check_inputs_not_owned(&mut |_| mock_callback(&mut call_count, false))
            .save(&persister)
            .expect("Persister shouldn't fail");
        assert_eq!(call_count, 1);

        let outputs_unknown = maybe_inputs_seen
            .check_no_inputs_seen_before(&mut |_| mock_callback(&mut call_count, false))
            .save(&persister)
            .expect("Persister shouldn't fail");
        assert_eq!(call_count, 2);

        let _wants_outputs = outputs_unknown
            .identify_receiver_outputs(&mut |_| mock_callback(&mut call_count, true))
            .save(&persister)
            .expect("Persister shouldn't fail");
        // there are 2 receiver outputs so we should expect this callback to run twice incrementing
        // call count twice
        assert_eq!(call_count, 4);
    }

    #[test]
    fn test_unchecked_proposal_transient_error() -> Result<(), BoxError> {
        let unchecked_proposal = unchecked_proposal_v2_from_test_vector();
        let receiver =
            v2::Receiver { state: unchecked_proposal, session_context: SHARED_CONTEXT.clone() };

        let expected_state = receiver.clone();
        let unchecked_proposal = receiver.check_broadcast_suitability(Some(FeeRate::MIN), |_| {
            Err(ImplementationError::new(Error::Implementation("mock error".into())))
        });

        match unchecked_proposal {
            MaybeFatalTransition(Err(Rejection::Transient(RejectTransient(
                Error::Implementation(error),
                current_state,
            )))) => {
                assert_eq!(
                    error.to_string(),
                    Error::Implementation("mock error".into()).to_string()
                );
                assert_eq!(current_state, expected_state);
            }
            _ => panic!("Expected Implementation error"),
        }

        Ok(())
    }

    #[test]
    fn test_unchecked_proposal_fatal_error() -> Result<(), BoxError> {
        let persister = InMemoryPersister::default();
        let unchecked_proposal = unchecked_proposal_v2_from_test_vector();
        let receiver =
            v2::Receiver { state: unchecked_proposal, session_context: SHARED_CONTEXT.clone() };

        let unchecked_proposal_err = receiver
            .check_broadcast_suitability(Some(FeeRate::MIN), |_| Ok(false))
            .save(&persister)
            .expect_err("should have replyable error");
        let has_error = unchecked_proposal_err.fatal_state().expect("should have state");

        let _err_req = has_error.create_error_request(EXAMPLE_URL)?;
        Ok(())
    }

    #[test]
    fn test_maybe_inputs_seen_transient_error() -> Result<(), BoxError> {
        let persister = InMemoryPersister::default();
        let unchecked_proposal = unchecked_proposal_v2_from_test_vector();
        let receiver =
            v2::Receiver { state: unchecked_proposal, session_context: SHARED_CONTEXT.clone() };

        let maybe_inputs_owned = receiver
            .assume_interactive_receiver()
            .save(&persister)
            .expect("Persister shouldn't fail");
        let expected_state = maybe_inputs_owned.clone();
        let maybe_inputs_seen = maybe_inputs_owned.check_inputs_not_owned(&mut |_| {
            Err(ImplementationError::new(Error::Implementation("mock error".into())))
        });

        match maybe_inputs_seen {
            MaybeFatalTransition(Err(Rejection::Transient(RejectTransient(
                Error::Implementation(error),
                current_state,
            )))) => {
                assert_eq!(
                    error.to_string(),
                    Error::Implementation("mock error".into()).to_string()
                );
                assert_eq!(current_state, expected_state);
            }
            _ => panic!("Expected Implementation error"),
        }

        Ok(())
    }

    #[test]
    fn test_outputs_unknown_transient_error() -> Result<(), BoxError> {
        let persister = InMemoryPersister::default();
        let unchecked_proposal = unchecked_proposal_v2_from_test_vector();
        let receiver =
            v2::Receiver { state: unchecked_proposal, session_context: SHARED_CONTEXT.clone() };

        let maybe_inputs_owned = receiver
            .assume_interactive_receiver()
            .save(&persister)
            .expect("Persister shouldn't fail");
        let maybe_inputs_seen = maybe_inputs_owned
            .check_inputs_not_owned(&mut |_| Ok(false))
            .save(&persister)
            .expect("Persister shouldn't fail");
        let expected_state = maybe_inputs_seen.clone();
        let outputs_unknown = maybe_inputs_seen.check_no_inputs_seen_before(&mut |_| {
            Err(ImplementationError::new(Error::Implementation("mock error".into())))
        });
        match outputs_unknown {
            MaybeFatalTransition(Err(Rejection::Transient(RejectTransient(
                Error::Implementation(error),
                current_state,
            )))) => {
                assert_eq!(
                    error.to_string(),
                    Error::Implementation("mock error".into()).to_string()
                );
                assert_eq!(current_state, expected_state);
            }
            _ => panic!("Expected Implementation error"),
        }

        Ok(())
    }

    #[test]
    fn test_wants_outputs_transient_error() -> Result<(), BoxError> {
        let persister = InMemoryPersister::default();
        let unchecked_proposal = unchecked_proposal_v2_from_test_vector();
        let receiver =
            v2::Receiver { state: unchecked_proposal, session_context: SHARED_CONTEXT.clone() };

        let maybe_inputs_owned = receiver
            .assume_interactive_receiver()
            .save(&persister)
            .expect("Persister shouldn't fail");
        let maybe_inputs_seen = maybe_inputs_owned
            .check_inputs_not_owned(&mut |_| Ok(false))
            .save(&persister)
            .expect("Persister should not fail");
        let outputs_unknown = maybe_inputs_seen
            .check_no_inputs_seen_before(&mut |_| Ok(false))
            .save(&persister)
            .expect("Persister should not fail");
        let expected_state = outputs_unknown.clone();
        let wants_outputs = outputs_unknown.identify_receiver_outputs(&mut |_| {
            Err(ImplementationError::new(Error::Implementation("mock error".into())))
        });
        match wants_outputs {
            MaybeFatalTransition(Err(Rejection::Transient(RejectTransient(
                Error::Implementation(error),
                current_state,
            )))) => {
                assert_eq!(
                    error.to_string(),
                    Error::Implementation("mock error".into()).to_string()
                );
                assert_eq!(current_state, expected_state);
            }
            _ => panic!("Expected Implementation error"),
        }

        Ok(())
    }

    #[test]
    fn transient_error_can_be_retried_from_returned_state() -> Result<(), BoxError> {
        let persister = InMemoryPersister::default();
        let receiver = receiver(unchecked_proposal_v2_from_test_vector());

        let err = receiver
            .check_broadcast_suitability(None, |_| Err("mock transient error".into()))
            .save(&persister)
            .expect_err("implementation failure should be transient");
        assert!(err.is_transient());
        assert!(!err.is_fatal());

        let receiver =
            err.transient_state().expect("transient error should return the current state");
        let _maybe_inputs_owned = receiver
            .check_broadcast_suitability(None, |_| Ok(true))
            .save(&persister)
            .expect("retry from the returned state should succeed");

        // The event log is identical to that of a run that never failed.
        assert_events(&persister, &[SessionEvent::CheckedBroadcastSuitability()], false);
        Ok(())
    }

    #[test]
    fn transient_state_matches_replay() -> Result<(), BoxError> {
        let persister = InMemoryPersister::default();
        persister.save_event(SessionEvent::Created(SHARED_CONTEXT.clone()))?;
        persister.save_event(SessionEvent::RetrievedOriginalPayload {
            original: unchecked_proposal_v2_from_test_vector().original,
            reply_key: None,
        })?;

        let (session, _history) = replay_event_log(&persister)?;
        let live_receiver = match session {
            ReceiveSession::UncheckedOriginalPayload(receiver) => receiver,
            other => panic!("Expected UncheckedOriginalPayload, got {other:?}"),
        };

        let err = live_receiver
            .check_broadcast_suitability(None, |_| Err("mock transient error".into()))
            .save(&persister)
            .expect_err("implementation failure should be transient");
        let state_from_error =
            err.transient_state().expect("transient error should return the current state");

        // Nothing was persisted, so replaying yields the same state the error carries.
        let (replayed, _history) = replay_event_log(&persister)?;
        assert_eq!(replayed, ReceiveSession::UncheckedOriginalPayload(state_from_error));
        Ok(())
    }

    #[test]
    fn test_create_error_request() -> Result<(), BoxError> {
        let mock_err = mock_err();
        let expected_json = serde_json::json!({
            "errorCode": "unavailable",
            "message": "Receiver error"
        });

        assert_eq!(mock_err.to_json(), expected_json);

        let receiver = Receiver {
            state: HasReplyableError {
                error_reply: mock_err.clone(),
                fallback_tx: Some(mock_fallback_tx()),
            },
            session_context: SHARED_CONTEXT.clone(),
        };

        let (_req, _ctx) = receiver.create_error_request(EXAMPLE_URL)?;

        Ok(())
    }

    #[test]
    fn test_create_error_request_expiration() -> Result<(), BoxError> {
        let now = crate::time::Time::now();
        let context = SessionContext { expiration: now, ..SHARED_CONTEXT.clone() };
        let receiver = Receiver {
            state: HasReplyableError {
                error_reply: mock_err(),
                fallback_tx: Some(mock_fallback_tx()),
            },
            session_context: context.clone(),
        };

        let expiration = receiver.create_error_request(EXAMPLE_URL);

        match expiration {
            Err(error) => assert_eq!(
                error.to_string(),
                CreateRequestError::from(InternalCreateRequestError::Expired(now)).to_string()
            ),
            Ok(_) => panic!("Expected session expiration error, got success"),
        }
        Ok(())
    }

    #[test]
    fn process_error_response_success_with_fallback_enters_pending_fallback() -> Result<(), BoxError>
    {
        let expected_tx = mock_fallback_tx();
        let receiver = receiver(HasReplyableError {
            error_reply: mock_err(),
            fallback_tx: Some(expected_tx.clone()),
        });
        let (req, ctx) = receiver.create_error_request(EXAMPLE_URL)?;
        let response = ohttp_response_for(&req.body, http::StatusCode::OK);
        let persister = InMemoryPersister::<SessionEvent>::default();

        let pending_fallback = receiver
            .process_error_response(&response, ctx)
            .save(&persister)?
            .expect("pending fallback should be returned");

        assert_eq!(pending_fallback.fallback_tx(), &expected_tx);
        assert_events(&persister, &[SessionEvent::ProtocolFailed], false);
        Ok(())
    }

    #[test]
    fn process_error_response_success_without_fallback_closes_session() -> Result<(), BoxError> {
        let receiver = receiver(HasReplyableError { error_reply: mock_err(), fallback_tx: None });
        let (req, ctx) = receiver.create_error_request(EXAMPLE_URL)?;
        let response = ohttp_response_for(&req.body, http::StatusCode::OK);
        let persister = InMemoryPersister::<SessionEvent>::default();

        let pending_fallback = receiver.process_error_response(&response, ctx).save(&persister)?;

        assert!(pending_fallback.is_none());
        assert_events(&persister, &[SessionEvent::Closed(SessionOutcome::Aborted)], true);
        Ok(())
    }

    #[test]
    fn process_error_response_fatal_with_fallback_enters_pending_fallback() -> Result<(), BoxError>
    {
        let expected_tx = mock_fallback_tx();
        let receiver = receiver(HasReplyableError {
            error_reply: mock_err(),
            fallback_tx: Some(mock_fallback_tx()),
        });
        let (req, ctx) = receiver.create_error_request(EXAMPLE_URL)?;
        let response = ohttp_response_for(&req.body, http::StatusCode::BAD_REQUEST);
        let persister = InMemoryPersister::<SessionEvent>::default();

        let err = receiver
            .process_error_response(&response, ctx)
            .save(&persister)
            .expect_err("fatal response should error");

        assert!(err.api_error_ref().is_some());
        let pending_fallback = err.fatal_state().expect("pending fallback should be carried");
        assert_eq!(pending_fallback.fallback_tx(), &expected_tx);
        assert_events(&persister, &[SessionEvent::ProtocolFailed], false);
        Ok(())
    }

    #[test]
    fn process_error_response_fatal_without_fallback_closes_session() -> Result<(), BoxError> {
        let receiver = receiver(HasReplyableError { error_reply: mock_err(), fallback_tx: None });
        let (req, ctx) = receiver.create_error_request(EXAMPLE_URL)?;
        let response = ohttp_response_for(&req.body, http::StatusCode::BAD_REQUEST);
        let persister = InMemoryPersister::<SessionEvent>::default();

        let err = receiver
            .process_error_response(&response, ctx)
            .save(&persister)
            .expect_err("fatal response should error");

        assert!(err.api_error_ref().is_some());
        assert_events(&persister, &[SessionEvent::Closed(SessionOutcome::Aborted)], true);
        Ok(())
    }

    #[test]
    fn process_error_response_transient_leaves_session_open() -> Result<(), BoxError> {
        let receiver = receiver(HasReplyableError {
            error_reply: mock_err(),
            fallback_tx: Some(mock_fallback_tx()),
        });
        let (req, ctx) = receiver.create_error_request(EXAMPLE_URL)?;
        let response = ohttp_response_for(&req.body, http::StatusCode::INTERNAL_SERVER_ERROR);
        let persister = InMemoryPersister::<SessionEvent>::default();

        let err = receiver
            .process_error_response(&response, ctx)
            .save(&persister)
            .expect_err("transient response should error");

        assert!(err.api_error_ref().is_some());
        assert_events(&persister, &[], false);
        Ok(())
    }

    #[test]
    fn payjoin_proposal_fatal_response_enters_pending_fallback() -> Result<(), BoxError> {
        let expected_tx = mock_fallback_tx();
        let psbt_context = PsbtContext {
            original_psbt: PARSED_ORIGINAL_PSBT.clone(),
            payjoin_psbt: PARSED_PAYJOIN_PROPOSAL.clone(),
        };
        let proposal = receiver(PayjoinProposal { psbt_context });
        let (req, ctx) = proposal.create_post_request(EXAMPLE_URL)?;
        let response = ohttp_response_for(&req.body, http::StatusCode::BAD_REQUEST);
        let persister = InMemoryPersister::<SessionEvent>::default();

        let err = proposal
            .process_response(&response, ctx)
            .save(&persister)
            .expect_err("fatal response should error");
        let pending_fallback = err.fatal_state().expect("pending fallback should be carried");

        assert_eq!(pending_fallback.fallback_tx(), &expected_tx);
        assert_events(&persister, &[SessionEvent::ProtocolFailed], false);
        Ok(())
    }

    #[test]
    fn test_create_post_request_expiration() -> Result<(), BoxError> {
        let now = crate::time::Time::now();
        let context = SessionContext { expiration: now, ..SHARED_CONTEXT.clone() };
        let psbt_context = PsbtContext {
            original_psbt: PARSED_ORIGINAL_PSBT.clone(),
            payjoin_psbt: PARSED_PAYJOIN_PROPOSAL.clone(),
        };
        let receiver =
            Receiver { state: PayjoinProposal { psbt_context }, session_context: context };

        let expiration = receiver.create_post_request(EXAMPLE_URL);

        match expiration {
            Err(error) => assert!(error.is_expired()),
            Ok(_) => panic!("Expected session expiration error, got success"),
        }
        Ok(())
    }

    #[test]
    fn default_max_fee_rate() {
        let persister = InMemoryPersister::default();
        let receiver = ReceiverBuilder::new(
            SHARED_CONTEXT.address.clone(),
            SHARED_CONTEXT.directory.as_str(),
            SHARED_CONTEXT.ohttp_keys.clone(),
        )
        .expect("constructor on test vector should not fail")
        .build()
        .save(&persister)
        .expect("Persister shouldn't fail");

        assert_eq!(receiver.session_context.max_fee_rate, FeeRate::BROADCAST_MIN);

        let non_default_max_fee_rate =
            FeeRate::from_sat_per_vb(1000).expect("Fee rate should be valid");
        let receiver = ReceiverBuilder::new(
            SHARED_CONTEXT.address.clone(),
            SHARED_CONTEXT.directory.as_str(),
            SHARED_CONTEXT.ohttp_keys.clone(),
        )
        .expect("constructor on test vector should not fail")
        .with_max_fee_rate(non_default_max_fee_rate)
        .build()
        .save(&persister)
        .expect("Persister shouldn't fail");
        assert_eq!(receiver.session_context.max_fee_rate, non_default_max_fee_rate);
    }

    #[test]
    fn default_expiration() {
        let persister = InMemoryPersister::default();

        let with_default_expiration = ReceiverBuilder::new(
            SHARED_CONTEXT.address.clone(),
            SHARED_CONTEXT.directory.as_str(),
            SHARED_CONTEXT.ohttp_keys.clone(),
        )
        .expect("constructor on test vector should not fail")
        .build()
        .save(&persister)
        .expect("Persister shouldn't fail");

        let short_expiration = Duration::from_secs(60);
        let with_short_expiration = ReceiverBuilder::new(
            SHARED_CONTEXT.address.clone(),
            SHARED_CONTEXT.directory.as_str(),
            SHARED_CONTEXT.ohttp_keys.clone(),
        )
        .expect("constructor on test vector should not fail")
        .with_expiration(short_expiration)
        .build()
        .save(&persister)
        .expect("Persister shouldn't fail");

        assert_ne!(
            with_short_expiration.session_context.expiration,
            with_default_expiration.session_context.expiration
        );
        assert!(
            with_short_expiration.session_context.expiration
                < with_default_expiration.session_context.expiration
        );
    }

    #[test]
    fn test_v2_pj_uri() {
        let uri =
            Receiver { state: Initialized {}, session_context: SHARED_CONTEXT.clone() }.pj_uri();
        assert_ne!(uri.extras().pj_param().endpoint().as_str(), EXAMPLE_URL);
        assert_eq!(uri.extras().output_substitution(), OutputSubstitution::Disabled);
    }

    #[test]
    /// Ensures output substitution is disabled for v1 proposals in v2 logic.
    fn test_unchecked_from_payload_disables_output_substitution_for_v1() {
        let base64 = ORIGINAL_PSBT;
        let query = "v=1";
        let payload = format!("{base64}\n{query}");
        let receiver = Receiver { state: Initialized {}, session_context: SHARED_CONTEXT.clone() };
        let proposal = receiver
            .unchecked_from_payload(&payload)
            .expect("unchecked_from_payload should parse valid v1 PSBT payload");
        assert_eq!(proposal.params.output_substitution, OutputSubstitution::Disabled);
    }

    #[test]
    fn test_getting_psbt_to_sign() {
        let provisional_proposal = ProvisionalProposal {
            psbt_context: PsbtContext {
                payjoin_psbt: PARSED_PAYJOIN_PROPOSAL.clone(),
                original_psbt: PARSED_ORIGINAL_PSBT.clone(),
            },
        };
        let receiver =
            Receiver { state: provisional_proposal, session_context: SHARED_CONTEXT.clone() };
        let psbt = receiver.psbt_to_sign();
        assert_eq!(psbt, PARSED_PAYJOIN_PROPOSAL.clone());
    }

    #[test]
    fn test_builder_with_amount() {
        let persister = InMemoryPersister::default();
        let amount = Amount::from_sat(100_000);
        let receiver = ReceiverBuilder::new(
            SHARED_CONTEXT.address.clone(),
            SHARED_CONTEXT.directory.as_str(),
            SHARED_CONTEXT.ohttp_keys.clone(),
        )
        .expect("constructor on test vector should not fail")
        .with_amount(amount)
        .build()
        .save(&persister)
        .expect("Persister shouldn't fail");

        assert_eq!(receiver.session_context.amount, Some(amount));

        let receiver = ReceiverBuilder::new(
            SHARED_CONTEXT.address.clone(),
            SHARED_CONTEXT.directory.as_str(),
            SHARED_CONTEXT.ohttp_keys.clone(),
        )
        .expect("constructor on test vector should not fail")
        .build()
        .save(&persister)
        .expect("Persister shouldn't fail");

        assert_eq!(receiver.session_context.amount, None);
    }

    #[test]
    fn cancel_initialized_closes_session() {
        let persister = InMemoryPersister::<SessionEvent>::default();
        receiver(Initialized {}).cancel().save(&persister).expect("save should succeed");

        assert_events(&persister, &[SessionEvent::Closed(SessionOutcome::Aborted)], true);
    }

    #[test]
    fn cancel_unchecked_original_payload_closes_session() {
        let original =
            OriginalPayload { psbt: PARSED_ORIGINAL_PSBT.clone(), params: Params::default() };
        let persister = InMemoryPersister::<SessionEvent>::default();
        receiver(UncheckedOriginalPayload { original })
            .cancel()
            .save(&persister)
            .expect("save should succeed");

        assert_events(&persister, &[SessionEvent::Closed(SessionOutcome::Aborted)], true);
    }

    #[test]
    fn cancel_has_fallback_enters_pending_fallback() {
        let original =
            OriginalPayload { psbt: PARSED_ORIGINAL_PSBT.clone(), params: Params::default() };
        let expected_tx = PARSED_ORIGINAL_PSBT.clone().extract_tx_unchecked_fee_rate();
        let persister = InMemoryPersister::<SessionEvent>::default();
        let pending_fallback = receiver(MaybeInputsOwned { original })
            .cancel()
            .save(&persister)
            .expect("save should succeed");

        assert_eq!(pending_fallback.fallback_tx(), &expected_tx);
        assert_events(&persister, &[SessionEvent::Cancelled], false);
    }

    #[test]
    fn cancel_replyable_error_with_fallback_enters_pending_fallback() {
        let expected_tx = mock_fallback_tx();
        let persister = InMemoryPersister::<SessionEvent>::default();
        let pending_fallback = receiver(HasReplyableError {
            error_reply: mock_err(),
            fallback_tx: Some(expected_tx.clone()),
        })
        .cancel()
        .save(&persister)
        .expect("save should succeed")
        .expect("pending fallback should be returned");

        assert_eq!(pending_fallback.fallback_tx(), &expected_tx);
        assert_events(&persister, &[SessionEvent::Cancelled], false);
    }

    #[test]
    fn cancel_replyable_error_without_fallback_closes_session() {
        let persister = InMemoryPersister::<SessionEvent>::default();
        let pending_fallback =
            receiver(HasReplyableError { error_reply: mock_err(), fallback_tx: None })
                .cancel()
                .save(&persister)
                .expect("save should succeed");

        assert!(pending_fallback.is_none());
        assert_events(&persister, &[SessionEvent::Closed(SessionOutcome::Aborted)], true);
    }

    #[test]
    fn replaying_cancel_event_sequences_reaches_expected_states() {
        let original =
            OriginalPayload { psbt: PARSED_ORIGINAL_PSBT.clone(), params: Params::default() };
        let expected_tx = PARSED_ORIGINAL_PSBT.clone().extract_tx_unchecked_fee_rate();
        let replyable_error = mock_err();

        let test_cases = vec![
            (
                vec![
                    SessionEvent::Created(SHARED_CONTEXT.clone()),
                    SessionEvent::Closed(SessionOutcome::Aborted),
                ],
                ReceiveSession::Closed(SessionOutcome::Aborted),
            ),
            (
                vec![
                    SessionEvent::Created(SHARED_CONTEXT.clone()),
                    SessionEvent::RetrievedOriginalPayload {
                        original: original.clone(),
                        reply_key: None,
                    },
                    SessionEvent::Closed(SessionOutcome::Aborted),
                ],
                ReceiveSession::Closed(SessionOutcome::Aborted),
            ),
            (
                vec![
                    SessionEvent::Created(SHARED_CONTEXT.clone()),
                    SessionEvent::RetrievedOriginalPayload {
                        original: original.clone(),
                        reply_key: None,
                    },
                    SessionEvent::CheckedBroadcastSuitability(),
                    SessionEvent::Cancelled,
                ],
                ReceiveSession::PendingFallback(Receiver {
                    state: PendingFallback { fallback_tx: expected_tx.clone() },
                    session_context: SHARED_CONTEXT.clone(),
                }),
            ),
            (
                vec![
                    SessionEvent::Created(SHARED_CONTEXT.clone()),
                    SessionEvent::RetrievedOriginalPayload {
                        original: original.clone(),
                        reply_key: None,
                    },
                    SessionEvent::CheckedBroadcastSuitability(),
                    SessionEvent::GotReplyableError(replyable_error.clone()),
                    SessionEvent::Cancelled,
                ],
                ReceiveSession::PendingFallback(Receiver {
                    state: PendingFallback { fallback_tx: expected_tx.clone() },
                    session_context: SHARED_CONTEXT.clone(),
                }),
            ),
            (
                vec![
                    SessionEvent::Created(SHARED_CONTEXT.clone()),
                    SessionEvent::RetrievedOriginalPayload {
                        original: original.clone(),
                        reply_key: None,
                    },
                    SessionEvent::CheckedBroadcastSuitability(),
                    SessionEvent::ProtocolFailed,
                ],
                ReceiveSession::PendingFallback(Receiver {
                    state: PendingFallback { fallback_tx: expected_tx.clone() },
                    session_context: SHARED_CONTEXT.clone(),
                }),
            ),
            (
                vec![
                    SessionEvent::Created(SHARED_CONTEXT.clone()),
                    SessionEvent::RetrievedOriginalPayload {
                        original: original.clone(),
                        reply_key: None,
                    },
                    SessionEvent::CheckedBroadcastSuitability(),
                    SessionEvent::GotReplyableError(replyable_error.clone()),
                    SessionEvent::ProtocolFailed,
                ],
                ReceiveSession::PendingFallback(Receiver {
                    state: PendingFallback { fallback_tx: expected_tx },
                    session_context: SHARED_CONTEXT.clone(),
                }),
            ),
            (
                vec![
                    SessionEvent::Created(SHARED_CONTEXT.clone()),
                    SessionEvent::RetrievedOriginalPayload {
                        original: original.clone(),
                        reply_key: None,
                    },
                    SessionEvent::GotReplyableError(replyable_error.clone()),
                    SessionEvent::Closed(SessionOutcome::Aborted),
                ],
                ReceiveSession::Closed(SessionOutcome::Aborted),
            ),
            (
                vec![
                    SessionEvent::Created(SHARED_CONTEXT.clone()),
                    SessionEvent::RetrievedOriginalPayload {
                        original: original.clone(),
                        reply_key: None,
                    },
                    SessionEvent::CheckedBroadcastSuitability(),
                    SessionEvent::Cancelled,
                    SessionEvent::Closed(SessionOutcome::Aborted),
                ],
                ReceiveSession::Closed(SessionOutcome::Aborted),
            ),
            (
                vec![
                    SessionEvent::Created(SHARED_CONTEXT.clone()),
                    SessionEvent::RetrievedOriginalPayload { original, reply_key: None },
                    SessionEvent::CheckedBroadcastSuitability(),
                    SessionEvent::ProtocolFailed,
                    SessionEvent::Closed(SessionOutcome::Aborted),
                ],
                ReceiveSession::Closed(SessionOutcome::Aborted),
            ),
        ];

        for (events, expected_state) in test_cases {
            let persister = InMemoryPersister::<SessionEvent>::default();
            for event in events {
                persister.save_event(event).expect("save should succeed");
            }
            let (state, _) = replay_event_log(&persister).expect("replay should succeed");
            assert_eq!(state, expected_state);
        }
    }

    #[test]
    fn replaying_replyable_error_from_unchecked_captures_no_fallback() {
        let state = unchecked_proposal_v2_from_test_vector();
        let error = mock_err();
        let session = ReceiveSession::UncheckedOriginalPayload(Receiver {
            state,
            session_context: SHARED_CONTEXT.clone(),
        });

        let replayed = session
            .process_event(SessionEvent::GotReplyableError(error.clone()))
            .expect("replyable error should replay");

        match replayed {
            ReceiveSession::HasReplyableError(receiver) => {
                assert_eq!(receiver.state.error_reply, error);
                assert_eq!(receiver.state.fallback_tx, None);
            }
            other => panic!("Expected HasReplyableError, got {other:?}"),
        }
    }

    #[test]
    fn replaying_replyable_error_from_initialized_captures_no_fallback() {
        let error = mock_err();
        let session = ReceiveSession::Initialized(Receiver {
            state: Initialized {},
            session_context: SHARED_CONTEXT.clone(),
        });

        let replayed = session
            .process_event(SessionEvent::GotReplyableError(error.clone()))
            .expect("replyable error should replay");

        match replayed {
            ReceiveSession::HasReplyableError(receiver) => {
                assert_eq!(receiver.state.error_reply, error);
                assert_eq!(receiver.state.fallback_tx, None);
            }
            other => panic!("Expected HasReplyableError, got {other:?}"),
        }
    }

    #[test]
    fn replaying_replyable_error_from_replyable_error_carries_some_fallback() {
        let expected_fallback = mock_fallback_tx();
        let error = mock_err();
        let session = ReceiveSession::HasReplyableError(Receiver {
            state: HasReplyableError {
                error_reply: mock_err(),
                fallback_tx: Some(expected_fallback.clone()),
            },
            session_context: SHARED_CONTEXT.clone(),
        });

        let replayed = session
            .process_event(SessionEvent::GotReplyableError(error.clone()))
            .expect("replyable error should replay");

        match replayed {
            ReceiveSession::HasReplyableError(receiver) => {
                assert_eq!(receiver.state.error_reply, error);
                assert_eq!(receiver.state.fallback_tx, Some(expected_fallback));
            }
            other => panic!("Expected HasReplyableError, got {other:?}"),
        }
    }

    #[test]
    fn replaying_replyable_error_from_replyable_error_carries_no_fallback() {
        let error = mock_err();
        let session = ReceiveSession::HasReplyableError(Receiver {
            state: HasReplyableError { error_reply: mock_err(), fallback_tx: None },
            session_context: SHARED_CONTEXT.clone(),
        });

        let replayed = session
            .process_event(SessionEvent::GotReplyableError(error.clone()))
            .expect("replyable error should replay");

        match replayed {
            ReceiveSession::HasReplyableError(receiver) => {
                assert_eq!(receiver.state.error_reply, error);
                assert_eq!(receiver.state.fallback_tx, None);
            }
            other => panic!("Expected HasReplyableError, got {other:?}"),
        }
    }
}
