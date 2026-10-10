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
use std::time::{Duration, SystemTime};

use bitcoin::psbt::Psbt;
use bitcoin::{Address, Amount, FeeRate, OutPoint, Script, ScriptBuf, Transaction, TxOut, Txid};
pub use error::{CreateRequestError, SessionError};
pub(crate) use error::{InternalCreateRequestError, InternalSessionError};
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
pub use session::{
    replay_event_log, replay_event_log_async, SessionEvent, SessionHistory, SessionOutcome,
    SessionStatus,
};
#[cfg(target_arch = "wasm32")]
use web_time::{Duration, SystemTime};

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
use crate::receive::{
    mark_checklist, parse_payload, ChecklistItem, InputOwnership, InputPair, InputSeenBefore,
    MarkedChecklistItem, OriginalPayload, OutputOwnership, PsbtContext,
};
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
        ShortId::from(self.receiver_key.public_key())
    }

    /// The mailbox ID where replies (the Proposal PSBT or errors) should
    /// be sent. For V1 requests this is the same as the proposal mailbox ID.
    // FIXME before the UncheckedOriginalPayload typestate is reached, this returns the
    // proposal mailbox ID. It doesn't make sense to reply before receiving
    // anything from the sender and at that point it's ambiguous whether it's a
    // v2 or v1 sender anyway. Ideally this should be impossible leveraging the
    // typestate machinery
    pub(crate) fn reply_mailbox_id(&self) -> ShortId {
        ShortId::from(self.reply_key.as_ref().unwrap_or(self.receiver_key.public_key()))
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
        fn original_psbt(&self) -> &bitcoin::Psbt;

        fn fallback_tx(&self) -> bitcoin::Transaction {
            self.original_psbt().clone().extract_tx_unchecked_fee_rate()
        }

        /// The finalized Payjoin proposal, once the sender may have received it.
        fn payjoin_psbt(&self) -> Option<&bitcoin::Psbt> { None }
    }

    impl FallbackTx for super::MaybeInputsOwned {
        fn original_psbt(&self) -> &bitcoin::Psbt { &self.original.psbt }
    }

    impl FallbackTx for super::MaybeInputsSeen {
        fn original_psbt(&self) -> &bitcoin::Psbt { &self.original.psbt }
    }

    impl FallbackTx for super::OutputsUnknown {
        fn original_psbt(&self) -> &bitcoin::Psbt { &self.original.psbt }
    }

    impl FallbackTx for super::WantsOutputs {
        fn original_psbt(&self) -> &bitcoin::Psbt { self.inner.original_psbt() }
    }

    impl FallbackTx for super::WantsInputs {
        fn original_psbt(&self) -> &bitcoin::Psbt { self.inner.original_psbt() }
    }

    impl FallbackTx for super::WantsFeeRange {
        fn original_psbt(&self) -> &bitcoin::Psbt { self.inner.original_psbt() }
    }

    impl FallbackTx for super::ProvisionalProposal {
        fn original_psbt(&self) -> &bitcoin::Psbt { &self.psbt_context.original_psbt }
    }

    // A post can reach the sender even if persisting the transition out of this state fails, so
    // the sender may hold this proposal.
    impl FallbackTx for super::PayjoinProposal {
        fn original_psbt(&self) -> &bitcoin::Psbt { &self.psbt_context.original_psbt }

        fn payjoin_psbt(&self) -> Option<&bitcoin::Psbt> { Some(&self.psbt_context.payjoin_psbt) }
    }

    impl FallbackTx for super::Monitor {
        fn original_psbt(&self) -> &bitcoin::Psbt { &self.psbt_context.original_psbt }

        fn payjoin_psbt(&self) -> Option<&bitcoin::Psbt> { Some(&self.psbt_context.payjoin_psbt) }
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

/// The fallback transaction for cancelled or failed receiver session.
///
/// See [`Receiver<PendingFallback>`] for further documentation.
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

    /// The prevouts the sender's original transaction spends.
    ///
    /// The fallback spends all of them, and so does any Payjoin proposal built from it, so a
    /// transaction spending any one of them conflicts with both.
    fn contested_prevouts(&self) -> impl Iterator<Item = OutPoint> + '_ {
        self.state.original_psbt().unsigned_tx.input.iter().map(|txin| txin.previous_output)
    }

    /// Classify a transaction against this session's Payjoin proposal and fallback.
    ///
    /// Pass every transaction the wallet receives to this method on each open session that has
    /// it, from [`Receiver<MaybeInputsOwned>`] through [`Receiver<Monitor>`]. The contested
    /// prevouts are the ones the sender's original transaction spends.
    /// The fallback spends all of them, and so does any proposal built from it. A transaction that
    /// spends none of them returns `None` after an outpoint comparison, before any hashing, so
    /// checking it against every session is cheap.
    ///
    /// Returns `None` if `tx` spends none of the contested prevouts, since it then says nothing
    /// about this session. Otherwise returns [`SettlementOutcome::Fallback`] if `tx` is the fallback,
    /// [`SettlementOutcome::Payjoin`] if it is the proposal, and [`SettlementOutcome::Unrecognized`]
    /// for any other spend. A proposal identical to the original reports as the fallback.
    ///
    /// Before [`Receiver<PayjoinProposal>`] the sender has no proposal to sign, so a state before
    /// it never reports [`SettlementOutcome::Payjoin`].
    ///
    /// If more than one transaction spends the contested prevouts, classify the one with the most
    /// confirmations.
    ///
    /// A transaction that spends only inputs the receiver contributed returns `None`. It makes the
    /// proposal invalid, but the fallback can still settle the session.
    pub fn classify_tx(&self, tx: &Transaction) -> Option<SettlementOutcome> {
        let spends_contested_prevout = tx
            .input
            .iter()
            .any(|txin| self.contested_prevouts().any(|prevout| prevout == txin.previous_output));
        if !spends_contested_prevout {
            return None;
        }

        let mut unsigned_tx = tx.clone();
        for txin in &mut unsigned_tx.input {
            txin.script_sig = ScriptBuf::new();
        }
        let unsigned_txid = unsigned_tx.compute_txid();

        if unsigned_txid == self.state.original_psbt().unsigned_tx.compute_txid() {
            return Some(SettlementOutcome::Fallback);
        }
        if let Some(payjoin_psbt) = self.state.payjoin_psbt() {
            if unsigned_txid == payjoin_psbt.unsigned_tx.compute_txid() {
                return Some(SettlementOutcome::Payjoin);
            }
        }
        Some(SettlementOutcome::Unrecognized)
    }

    /// Whether the sender's signatures leave the Payjoin proposal's transaction ID unchanged.
    ///
    /// If every sender input is native SegWit, the sender's final signatures
    /// live in the witness and each script_sig stays empty. If any sender
    /// input finalizes with a non-empty script_sig — legacy inputs, whose
    /// signatures live there, but also P2SH-wrapped SegWit inputs, whose
    /// script_sig carries the redeem script push — that script_sig is part of
    /// the txid preimage and changes the transaction ID.
    ///
    /// This checks only the sender's inputs. A legacy or P2SH-wrapped input
    /// the receiver contributes also carries a script_sig, so a transaction ID
    /// computed from the unsigned proposal can be wrong even when this returns
    /// true. [`Receiver::classify_tx`] recognizes the proposal either way.
    #[deprecated(
        since = "0.0.0-unreleased",
        note = "checks only the sender's inputs; use `Receiver::classify_tx`"
    )]
    pub fn proposal_txid_is_stable(&self) -> bool { self.sender_script_sigs_are_empty() }

    /// Whether every sender input finalizes with an empty script_sig.
    fn sender_script_sigs_are_empty(&self) -> bool {
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

/// Empty initial state awaiting the sender's Original PSBT.
///
/// See [`Receiver<Initialized>`] for further documentation.
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

/// The sender's Original PSBT, received but not yet validated.
///
/// See [`Receiver<UncheckedOriginalPayload>`] for further documentation.
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
///
/// To perform the broadcast check without a synchronous callback, use
/// [`Receiver<UncheckedOriginalPayload>::extract_tx_to_check_broadcast_suitability`]
/// and [`Receiver<UncheckedOriginalPayload>::apply_broadcast_suitability`].
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
        let tx = self.extract_tx_to_check_broadcast_suitability();
        match can_broadcast(&tx) {
            Ok(is_broadcast_suitable) =>
                self.apply_broadcast_suitability(min_fee_rate, is_broadcast_suitable),
            Err(e) => MaybeFatalTransition::transient(Error::Implementation(e), self),
        }
    }

    /// Extract the Original PSBT transaction so the caller can check that it is
    /// suitable for broadcast, ensuring it can be used as a fallback if the payjoin
    /// does not complete.
    ///
    /// Submit the result of the check to
    /// [`Receiver<UncheckedOriginalPayload>::apply_broadcast_suitability`].
    ///
    /// Returns the extracted [`bitcoin::Transaction`].
    pub fn extract_tx_to_check_broadcast_suitability(&self) -> bitcoin::Transaction {
        self.original.psbt.clone().extract_tx_unchecked_fee_rate()
    }

    /// Apply the result of the broadcast suitability check to advance the state machine.
    ///
    /// Use [`Receiver<UncheckedOriginalPayload>::extract_tx_to_check_broadcast_suitability`]
    /// to obtain the transaction that needs to be checked. Optionally enforce a minimum fee
    /// rate on the Original PSBT to further raise the cost of probing attacks.
    ///
    /// Returns a [`MaybeFatalTransition`] that, once successfully persisted, yields a
    /// [`Receiver<MaybeInputsOwned>`] to continue validation.
    pub fn apply_broadcast_suitability(
        self,
        min_fee_rate: Option<FeeRate>,
        is_broadcast_suitable: bool,
    ) -> MaybeFatalTransition<
        SessionEvent,
        Receiver<MaybeInputsOwned>,
        Error,
        Receiver<HasReplyableError>,
        Self,
    > {
        match self.state.original.apply_broadcast_suitability(min_fee_rate, is_broadcast_suitable) {
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

/// The Original PSBT with inputs not yet checked for receiver ownership.
///
/// See [`Receiver<MaybeInputsOwned>`] for further documentation.
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
///
/// To perform this check without a synchronous callback, use
/// [`Receiver<MaybeInputsOwned>::inputs_owned_checklist`] and
/// [`Receiver<MaybeInputsOwned>::apply_inputs_owned_checklist`].
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
        is_owned: &mut impl FnMut(&OutPoint) -> Result<bool, ImplementationError>,
    ) -> MaybeFatalTransition<
        SessionEvent,
        Receiver<MaybeInputsSeen>,
        Error,
        Receiver<HasReplyableError>,
        Self,
    > {
        match mark_checklist(self.inputs_owned_checklist(), is_owned) {
            Ok(marked_checklist) => self.apply_inputs_owned_checklist(marked_checklist),
            Err(e) => MaybeFatalTransition::transient(Error::Implementation(e), self),
        }
    }

    /// Get the [`ChecklistItem`]s holding the input outpoints that need to be checked for
    /// ownership by the receiver, preventing an attacker from spending the receiver's
    /// own inputs.
    ///
    /// Each [`ChecklistItem`] must be marked with its result to obtain a
    /// [`MarkedChecklistItem`], which can then be collected and submitted to
    /// [`Receiver<MaybeInputsOwned>::apply_inputs_owned_checklist`].
    pub fn inputs_owned_checklist(
        &self,
    ) -> impl Iterator<Item = ChecklistItem<InputOwnership>> + use<> {
        self.state.original.inputs_owned_checklist()
    }

    /// Apply the input ownership checklist results to advance the state machine.
    ///
    /// Use [`Receiver<MaybeInputsOwned>::inputs_owned_checklist`] to obtain the items
    /// that need to be checked.
    ///
    /// Returns a [`MaybeFatalTransition`] that, once successfully persisted, yields a
    /// [`Receiver<MaybeInputsSeen>`] to continue validation.
    pub fn apply_inputs_owned_checklist(
        self,
        marked_checklist: impl IntoIterator<Item = MarkedChecklistItem<InputOwnership>>,
    ) -> MaybeFatalTransition<
        SessionEvent,
        Receiver<MaybeInputsSeen>,
        Error,
        Receiver<HasReplyableError>,
        Self,
    > {
        match self.state.original.apply_inputs_owned_checklist(marked_checklist) {
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

/// The Original PSBT with inputs not yet checked against previously seen inputs.
///
/// See [`Receiver<MaybeInputsSeen>`] for further documentation.
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
///
/// To perform this check without a synchronous callback, use
/// [`Receiver<MaybeInputsSeen>::inputs_seen_checklist`] and
/// [`Receiver<MaybeInputsSeen>::apply_inputs_seen_checklist`].
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
        match mark_checklist(self.inputs_seen_checklist(), is_known) {
            Ok(marked_checklist) => self.apply_inputs_seen_checklist(marked_checklist),
            Err(e) => MaybeFatalTransition::transient(Error::Implementation(e), self),
        }
    }

    /// Get the [`ChecklistItem`]s holding the input outpoints that need to be checked
    /// for whether the receiver has seen them before, preventing input probing and
    /// replay attacks.
    ///
    /// Each [`ChecklistItem`] must be marked with its result to obtain a
    /// [`MarkedChecklistItem`], which can then be collected and submitted to
    /// [`Receiver<MaybeInputsSeen>::apply_inputs_seen_checklist`].
    pub fn inputs_seen_checklist(
        &self,
    ) -> impl Iterator<Item = ChecklistItem<InputSeenBefore>> + use<> {
        self.state.original.inputs_seen_checklist()
    }

    /// Apply the inputs-seen checklist results to advance the state machine.
    ///
    /// Use [`Receiver<MaybeInputsSeen>::inputs_seen_checklist`] to obtain the items
    /// that need to be checked.
    ///
    /// Returns a [`MaybeFatalTransition`] that, once successfully persisted, yields a
    /// [`Receiver<OutputsUnknown>`] to continue validation.
    pub fn apply_inputs_seen_checklist(
        self,
        marked_checklist: impl IntoIterator<Item = MarkedChecklistItem<InputSeenBefore>>,
    ) -> MaybeFatalTransition<
        SessionEvent,
        Receiver<OutputsUnknown>,
        Error,
        Receiver<HasReplyableError>,
        Self,
    > {
        match self.state.original.apply_inputs_seen_checklist(marked_checklist) {
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

/// The Original PSBT with receiver outputs not yet identified.
///
/// See [`Receiver<OutputsUnknown>`] for further documentation.
#[derive(Debug, Clone, PartialEq)]
pub struct OutputsUnknown {
    original: OriginalPayload,
}

/// Typestate to check that the outputs of the Original PSBT actually pay the receiver.
///
/// The receiver should only accept Original PSBTs from the sender that actually send
/// them money. Call [`Receiver<OutputsUnknown>::identify_receiver_outputs`] to advance
/// to [`Receiver<WantsOutputs>`] to continue the proposal.
///
/// To perform this check without a synchronous callback, use
/// [`Receiver<OutputsUnknown>::outputs_owned_checklist`] and
/// [`Receiver<OutputsUnknown>::apply_outputs_owned_checklist`].
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
        match mark_checklist(self.outputs_owned_checklist(), &mut |script: &ScriptBuf| {
            is_receiver_output(script.as_script())
        }) {
            Ok(marked_checklist) => self.apply_outputs_owned_checklist(marked_checklist),
            Err(e) => MaybeFatalTransition::transient(Error::Implementation(e), self),
        }
    }

    /// Get the [`ChecklistItem`]s holding the output scripts that need to be checked
    /// for ownership by the receiver, ensuring at least one output pays the receiver.
    ///
    /// Each [`ChecklistItem`] must be marked with its result to obtain a
    /// [`MarkedChecklistItem`], which can then be collected and submitted to
    /// [`Receiver<OutputsUnknown>::apply_outputs_owned_checklist`].
    pub fn outputs_owned_checklist(
        &self,
    ) -> impl Iterator<Item = ChecklistItem<OutputOwnership>> + use<> {
        self.state.original.outputs_owned_checklist()
    }

    /// Apply the output ownership checklist results to advance the state machine.
    ///
    /// Use [`Receiver<OutputsUnknown>::outputs_owned_checklist`] to obtain the items
    /// that need to be checked.
    ///
    /// If the sender designated a receiver output for fee subtraction, that designation
    /// is cleared so the receiver does not accidentally subtract fees from their own output.
    ///
    /// Returns a [`MaybeFatalTransition`] that, once successfully persisted, yields a
    /// [`Receiver<WantsOutputs>`] to continue the proposal.
    pub fn apply_outputs_owned_checklist(
        self,
        marked_checklist: impl IntoIterator<Item = MarkedChecklistItem<OutputOwnership>>,
    ) -> MaybeFatalTransition<
        SessionEvent,
        Receiver<WantsOutputs>,
        Error,
        Receiver<HasReplyableError>,
        Self,
    > {
        let fallback_tx = Some(self.state.fallback_tx());
        match self.state.original.clone().apply_outputs_owned_checklist(marked_checklist) {
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

/// The checked Original PSBT awaiting receiver output substitution and commitment.
///
/// See [`Receiver<WantsOutputs>`] for further documentation.
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
    /// If `output_script` is not the receiver wallet's own and the receiver contributes no input,
    /// the proposal touches nothing the wallet syncs. Watch `output_script` to find the proposal
    /// when it settles, and keep watching it across restarts.
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

/// The checked proposal awaiting receiver input contributions and commitment.
///
/// See [`Receiver<WantsInputs>`] for further documentation.
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

/// The checked proposal awaiting the receiver's fee contribution.
///
/// See [`Receiver<WantsFeeRange>`] for further documentation.
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

/// The modified proposal ready to be signed and finalized.
///
/// See [`Receiver<ProvisionalProposal>`] for further documentation.
#[derive(Debug, Clone, PartialEq)]
pub struct ProvisionalProposal {
    psbt_context: PsbtContext,
}

/// Typestate for a checked proposal that the receiver has modified the outputs and
/// inputs of, and is ready to be signed and finalized.
///
/// Call [`Receiver<ProvisionalProposal>::finalize_proposal`] to advance to
/// [`Receiver<PayjoinProposal>`].
///
/// To sign without a synchronous callback, use
/// [`Receiver<ProvisionalProposal>::psbt_to_sign`] and
/// [`Receiver<ProvisionalProposal>::finalize_signed_proposal`].
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
        let psbt = self.psbt_to_sign();
        let signed_psbt = wallet_process_psbt(&psbt);
        match signed_psbt {
            Ok(signed_psbt) => self.finalize_signed_proposal(&signed_psbt),
            Err(e) => MaybeTransientTransition::transient(e, self),
        }
    }

    /// Extract the PSBT that needs to be signed by the receiver's wallet.
    ///
    /// In some applications the entity that progresses the typestate is different from the
    /// entity that has access to the private keys, so the PSBT to sign must be accessible to
    /// such implementers. Submit the signed PSBT to
    /// [`Receiver<ProvisionalProposal>::finalize_signed_proposal`].
    ///
    /// Returns the Payjoin proposal [`Psbt`] to be signed.
    pub fn psbt_to_sign(&self) -> Psbt { self.state.psbt_context.psbt_to_sign() }

    /// Finalize the receiver-signed Payjoin proposal into a PSBT the sender will find
    /// acceptable before they sign and broadcast it to the network.
    ///
    /// Use [`Receiver<ProvisionalProposal>::psbt_to_sign`] to obtain the unsigned PSBT for
    /// the receiver to sign and return here.
    ///
    /// Returns a [`MaybeTransientTransition`] that, once successfully persisted, yields the
    /// final [`Receiver<PayjoinProposal>`].
    pub fn finalize_signed_proposal(
        self,
        signed_psbt: &Psbt,
    ) -> MaybeTransientTransition<SessionEvent, Receiver<PayjoinProposal>, ImplementationError, Self>
    {
        let original_psbt = self.state.psbt_context.original_psbt.clone();
        let payjoin_psbt =
            match self.state.psbt_context.finalize_signed_proposal(signed_psbt.clone()) {
                Ok(payjoin_psbt) => payjoin_psbt,
                Err(e) => {
                    return MaybeTransientTransition::transient(e, self);
                }
            };
        let psbt_context = PsbtContext { payjoin_psbt: payjoin_psbt.clone(), original_psbt };
        let payjoin_proposal = PayjoinProposal { psbt_context: psbt_context.clone() };
        MaybeTransientTransition::success(
            SessionEvent::FinalizedProposal(payjoin_psbt),
            Receiver { state: payjoin_proposal, session_context: self.session_context },
        )
    }

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

/// The signed and finalized Payjoin proposal to send to the sender.
///
/// See [`Receiver<PayjoinProposal>`] for further documentation.
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
            let sender_mailbox = ShortId::from(e);
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

/// Replyable error hit during validation.
///
/// See [`Receiver<HasReplyableError>`] for further documentation.
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

/// Completed Payjoin proposal that has been posted to the sender.
///
/// See [`Receiver<Monitor>`] for further documentation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Monitor {
    psbt_context: PsbtContext,
}

/// Which transaction spent the prevouts of a session's original transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SettlementOutcome {
    /// This session's Payjoin proposal settled.
    Payjoin,
    /// This session's fallback transaction settled: paid, without cooperation.
    Fallback,
    /// Some other transaction spent the original transaction's prevouts, for example a fee bump
    /// of the fallback or the sender re-spending elsewhere. It conflicts with both the proposal and
    /// the fallback, and says nothing about whether the receiver was paid.
    Unrecognized,
}

/// Completed Payjoin proposal that has been posted to the sender.
///
/// As in every open session, pass each transaction the wallet receives to
/// [`classify_tx`](Receiver::classify_tx), and call `close` once the result meets your
/// confirmation bar. Ordinary wallet sync by script finds both candidates: the fallback
/// pays the receiver's address, and the proposal spends the receiver's inputs or pays its outputs.
/// The wallet supplies chain access and chooses that bar.
///
/// If nothing settles the session by a deadline of the wallet's choosing, such as
/// [`mailbox_expiration`](Receiver::mailbox_expiration), [`cancel`](Receiver::cancel) it and
/// broadcast the fallback. A cancelled session cannot recognize the sender's Payjoin, and closes as
/// [`SessionOutcome::Aborted`] whichever transaction confirms.
///
/// A proposal that spends no receiver input and pays only scripts the receiver's wallet does not
/// own, such as one forwarding the payment to a third party, touches nothing the wallet syncs. A
/// wallet that substitutes outputs this way must watch those scripts itself, across restarts.
impl Receiver<Monitor> {
    /// Close the session once the wallet has settled its outcome.
    ///
    /// Call this when [`classify_tx`](Receiver::classify_tx) has returned a verdict for a
    /// transaction that meets the wallet's confirmation bar, whichever verdict it is. To give up on
    /// a session nothing has settled, [`cancel`](Receiver::cancel) it and broadcast the fallback.
    pub fn close(self) -> TerminalTransition<SessionEvent, ()> {
        TerminalTransition::new(SessionEvent::Closed(SessionOutcome::PayjoinProposalSent), ())
    }

    /// When the session's mailbox expires.
    ///
    /// The receiver set this when it created the session, so it says nothing about when the
    /// proposal was posted. A posted session outlives its mailbox and stays open until the wallet
    /// closes or cancels it.
    pub fn mailbox_expiration(&self) -> SystemTime {
        self.session_context.expiration.to_system_time()
    }

    /// The txid the Payjoin proposal will have on chain, if the receiver can know it in advance.
    ///
    /// The txid includes the script_sigs of the receiver's finalized inputs, which a legacy or
    /// P2SH-wrapped receiver input fills. `None` if a sender input finalizes with a non-empty
    /// script_sig, since the sender's signature then changes the txid.
    fn stable_payjoin_txid(&self) -> Option<Txid> {
        if !self.sender_script_sigs_are_empty() {
            return None;
        }
        // The posted proposal carries the receiver's finalized inputs and no sender signatures,
        // and the sender adds only witnesses, so extracting it yields the broadcast script_sigs.
        let payjoin_tx =
            self.state.psbt_context.payjoin_psbt.clone().extract_tx_unchecked_fee_rate();
        Some(payjoin_tx.compute_txid())
    }

    /// Check the network for the Payjoin or fallback transaction via the `find_transaction`
    /// callback.
    ///
    /// Returns a [`MaybeFatalOrSuccessTransition`] that, once successfully persisted, either
    /// concludes the session if a transaction is found, or yields a [`Receiver<Monitor>`] to
    /// remain in stasis if no transaction is found yet.
    ///
    /// Probes only the proposal and fallback txids and closes on the first match. When a sender
    /// input finalizes with a non-empty script_sig, the sender's signature changes the proposal's
    /// txid, so it closes the session without checking.
    #[deprecated(since = "0.0.0-unreleased", note = "use `classify_tx` and `close`")]
    pub fn check_for_transaction(
        self,
        find_transaction: impl Fn(Txid) -> Result<Option<bitcoin::Transaction>, ImplementationError>,
    ) -> MaybeFatalOrSuccessTransition<SessionEvent, Self, Error> {
        let fallback_tx = self.state.fallback_tx();

        // If the fallback transaction included any non-SegWit inputs, then the transaction ID of
        // the Payjoin proposal is going to change when the sender signs their non-SegWit address
        // one more time. This method can only probe by txid, so it concludes the session.
        let payjoin_txid = match self.stable_payjoin_txid() {
            Some(txid) => txid,
            None =>
                return MaybeFatalOrSuccessTransition::success(SessionEvent::Closed(
                    SessionOutcome::PayjoinProposalSent,
                )),
        };
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
                // Close only on this session's proposal, recording the txid that settled it.
                if let Some(SettlementOutcome::Payjoin) = self.classify_tx(&tx) {
                    return MaybeFatalOrSuccessTransition::success(SessionEvent::Closed(
                        SessionOutcome::Success(tx_id),
                    ));
                }
            }
            Ok(None) => {}
            Err(e) =>
                return MaybeFatalOrSuccessTransition::transient(Error::Implementation(e), self),
        }

        // If the Payjoin proposal was not found, check the fallback transaction, as it is
        // the second of two transactions whose IDs the receiver is aware of.
        match find_transaction(fallback_tx.compute_txid()) {
            Ok(Some(tx)) =>
                if let Some(SettlementOutcome::Fallback) = self.classify_tx(&tx) {
                    return MaybeFatalOrSuccessTransition::success(SessionEvent::Closed(
                        SessionOutcome::FallbackBroadcasted,
                    ));
                },
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
    use crate::persist::{InMemoryPersister, RejectTransient, Rejection, SessionPersister};
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
        assert_eq!(monitor.stable_payjoin_txid(), Some(payjoin_tx.compute_txid()));

        // The wallet finds the Payjoin or the fallback by txid and classifies it.
        assert_eq!(monitor.classify_tx(&payjoin_tx), Some(SettlementOutcome::Payjoin));
        assert_eq!(
            monitor.fallback_tx().compute_txid(),
            original_tx.compute_txid(),
            "the fallback is found by its txid"
        );
        assert_eq!(monitor.classify_tx(&original_tx), Some(SettlementOutcome::Fallback));

        // Once the result meets the wallet's confirmation bar, it closes the session.
        let persister = InMemoryPersister::default();
        monitor.clone().close().save(&persister).expect("InMemoryPersister shouldn't fail");
        assert!(persister.inner.lock().expect("Shouldn't be poisoned").is_closed);
        assert_eq!(
            persister.inner.lock().expect("Shouldn't be poisoned").events,
            vec![SessionEvent::Closed(SessionOutcome::PayjoinProposalSent)]
        );

        // Fallback transaction is non-SegWit address type, so the proposal's txid is unknowable
        // in advance, but classify_tx still recognizes the proposal and the fallback.
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
        assert_eq!(monitor.stable_payjoin_txid(), None);

        let signed_payjoin_tx =
            with_perturbed_txid(parsed_payjoin_proposal_p2pkh.unsigned_tx.clone());
        assert_ne!(
            signed_payjoin_tx.compute_txid(),
            parsed_payjoin_proposal_p2pkh.unsigned_tx.compute_txid()
        );
        assert_eq!(monitor.classify_tx(&signed_payjoin_tx), Some(SettlementOutcome::Payjoin));
        let p2pkh_fallback_tx = parsed_original_psbt_p2pkh.extract_tx_unchecked_fee_rate();
        assert_eq!(monitor.classify_tx(&p2pkh_fallback_tx), Some(SettlementOutcome::Fallback));

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
        assert_eq!(monitor.stable_payjoin_txid(), None);

        // The redeem script push changes the fallback's txid too, and classify_tx
        // still recognizes it.
        assert_eq!(monitor.classify_tx(&monitor.fallback_tx()), Some(SettlementOutcome::Fallback));

        Ok(())
    }

    #[test]
    fn test_stable_payjoin_txid_includes_receiver_script_sig() {
        // A native SegWit sender with a P2SH-wrapped or legacy receiver input: the receiver's
        // finalized script_sig is in the broadcast transaction, so the unsigned proposal's txid
        // never appears on chain.
        let mut psbt_ctx = native_segwit_psbt_context();
        psbt_ctx.payjoin_psbt.inputs[1].final_script_sig = Some(ScriptBuf::from_bytes(vec![0x51]));
        let unsigned_txid = psbt_ctx.payjoin_psbt.unsigned_tx.compute_txid();
        let mut broadcast_tx = psbt_ctx.payjoin_psbt.clone().extract_tx_unchecked_fee_rate();
        let mut sender_witness = Witness::new();
        sender_witness.push([0x30; 71]); // dummy signature
        sender_witness.push([0x02; 33]); // dummy compressed pubkey
        broadcast_tx.input[0].witness = sender_witness;
        let monitor = Receiver {
            state: Monitor { psbt_context: psbt_ctx },
            session_context: SHARED_CONTEXT.clone(),
        };

        assert_ne!(broadcast_tx.compute_txid(), unsigned_txid);
        assert_eq!(monitor.stable_payjoin_txid(), Some(broadcast_tx.compute_txid()));
        assert_eq!(monitor.classify_tx(&broadcast_tx), Some(SettlementOutcome::Payjoin));
    }

    #[test]
    #[allow(deprecated)]
    fn test_check_for_transaction_regression() {
        // The deprecated method probes the expected Payjoin txid, then the fallback txid, and
        // closes on the first match. The receiver's script_sig makes the expected txid differ
        // from the unsigned proposal's.
        let mut psbt_ctx = native_segwit_psbt_context();
        psbt_ctx.payjoin_psbt.inputs[1].final_script_sig = Some(ScriptBuf::from_bytes(vec![0x51]));
        let payjoin_tx = psbt_ctx.payjoin_psbt.clone().extract_tx_unchecked_fee_rate();
        let fallback_tx = psbt_ctx.original_psbt.clone().extract_tx_unchecked_fee_rate();
        let monitor = Receiver {
            state: Monitor { psbt_context: psbt_ctx },
            session_context: SHARED_CONTEXT.clone(),
        };
        let check_for = |broadcast: &Transaction| {
            let persister = InMemoryPersister::default();
            monitor
                .clone()
                .check_for_transaction(|txid| {
                    Ok((txid == broadcast.compute_txid()).then(|| broadcast.clone()))
                })
                .save(&persister)
                .expect("InMemoryPersister shouldn't fail");
            let inner = persister.inner.lock().expect("Shouldn't be poisoned");
            assert!(inner.is_closed);
            inner.events.last().cloned()
        };

        assert_eq!(
            check_for(&payjoin_tx),
            Some(SessionEvent::Closed(SessionOutcome::Success(payjoin_tx.compute_txid())))
        );
        assert_eq!(
            check_for(&fallback_tx),
            Some(SessionEvent::Closed(SessionOutcome::FallbackBroadcasted))
        );
    }

    #[test]
    #[allow(deprecated)]
    fn test_proposal_txid_is_stable_regression() {
        // The deprecated method checks only the sender's inputs: stable for a native SegWit
        // sender, unstable for the P2SH-wrapped SegWit sender in the BIP78 vectors.
        let native_segwit_monitor = Receiver {
            state: Monitor { psbt_context: native_segwit_psbt_context() },
            session_context: SHARED_CONTEXT.clone(),
        };
        assert!(native_segwit_monitor.proposal_txid_is_stable());
        assert!(!segwit_monitor().proposal_txid_is_stable());
    }

    fn segwit_monitor() -> Receiver<Monitor> {
        let psbt_ctx = PsbtContext {
            original_psbt: PARSED_ORIGINAL_PSBT.clone(),
            payjoin_psbt: PARSED_PAYJOIN_PROPOSAL.clone(),
        };
        Receiver {
            state: Monitor { psbt_context: psbt_ctx },
            session_context: SHARED_CONTEXT.clone(),
        }
    }

    /// A monitor whose proposal is identical to the sender's original transaction: no receiver
    /// input and no substituted output, so the proposal and the fallback are one transaction.
    fn identical_proposal_monitor() -> Receiver<Monitor> {
        let original = PARSED_ORIGINAL_PSBT.clone();
        let psbt_ctx = PsbtContext { original_psbt: original.clone(), payjoin_psbt: original };
        Receiver {
            state: Monitor { psbt_context: psbt_ctx },
            session_context: SHARED_CONTEXT.clone(),
        }
    }

    /// A monitor whose proposal substitutes outputs but contributes no input (output-substitution
    /// or cut-through Payjoin): same inputs as the sender's original, a different output set.
    fn cutthrough_monitor() -> Receiver<Monitor> {
        let original = PARSED_ORIGINAL_PSBT.clone();
        let mut proposal = original.clone();
        proposal.unsigned_tx.output[0].script_pubkey =
            ScriptBuf::from_bytes(vec![0x6a, 0x01, 0x2a]);
        let psbt_ctx = PsbtContext { original_psbt: original, payjoin_psbt: proposal };
        Receiver {
            state: Monitor { psbt_context: psbt_ctx },
            session_context: SHARED_CONTEXT.clone(),
        }
    }

    /// The fallback transaction, finalized as the sender would broadcast it.
    fn fallback_tx() -> Transaction { PARSED_ORIGINAL_PSBT.clone().extract_tx().expect("valid tx") }

    /// Return a clone of `tx` with a different txid (a non-empty script_sig on the first input),
    /// simulating a non-SegWit signature, or malleation of one, changing the txid without
    /// changing anything else.
    fn with_perturbed_txid(mut tx: Transaction) -> Transaction {
        tx.input[0].script_sig = ScriptBuf::from_bytes(vec![0x51]); // OP_TRUE, arbitrary
        tx
    }

    /// Return a clone of `tx` that spends the same prevouts but is a different transaction, as
    /// when the sender re-spends its inputs elsewhere.
    fn respent(mut tx: Transaction) -> Transaction {
        tx.output[0].value = Amount::from_sat(tx.output[0].value.to_sat() - 1);
        tx
    }

    #[test]
    fn test_monitor_internal_getters() {
        let monitor = segwit_monitor();
        let original_tx = fallback_tx();

        // The BIP78 test vectors spend P2SH-wrapped SegWit inputs, so the txid is unstable.
        assert_eq!(monitor.stable_payjoin_txid(), None);
        assert_eq!(monitor.fallback_tx().compute_txid(), original_tx.compute_txid());

        let contested_prevouts: Vec<OutPoint> = monitor.contested_prevouts().collect();
        let expected_contested_prevouts: Vec<OutPoint> =
            original_tx.input.iter().map(|txin| txin.previous_output).collect();
        assert_eq!(contested_prevouts, expected_contested_prevouts);
    }

    #[test]
    fn test_classify_tx_ignores_unrelated_tx() {
        use bitcoin::hashes::Hash as _;

        // A transaction spending none of the contested prevouts says nothing about the session.
        let monitor = segwit_monitor();
        let mut unrelated = PARSED_PAYJOIN_PROPOSAL.clone().unsigned_tx;
        for txin in unrelated.input.iter_mut() {
            txin.previous_output = OutPoint { txid: Txid::all_zeros(), vout: 9 };
        }
        assert_eq!(monitor.classify_tx(&unrelated), None);
    }

    #[test]
    fn test_classify_tx_payjoin() {
        let monitor = segwit_monitor();
        let payjoin_tx = PARSED_PAYJOIN_PROPOSAL.clone().unsigned_tx;

        assert_eq!(monitor.classify_tx(&payjoin_tx), Some(SettlementOutcome::Payjoin));
    }

    #[test]
    fn test_classify_tx_payjoin_with_changed_txid() {
        // A non-SegWit sender's signature changes the proposal's txid. Identity ignores
        // script_sig, so this is still the Payjoin.
        let monitor = segwit_monitor();
        let signed_tx = with_perturbed_txid(PARSED_PAYJOIN_PROPOSAL.clone().unsigned_tx);
        assert_ne!(signed_tx.compute_txid(), PARSED_PAYJOIN_PROPOSAL.unsigned_tx.compute_txid());

        assert_eq!(monitor.classify_tx(&signed_tx), Some(SettlementOutcome::Payjoin));
    }

    #[test]
    fn test_classify_tx_payjoin_without_receiver_input() {
        // An output-substitution Payjoin carries no receiver input, and is still identified.
        let monitor = cutthrough_monitor();
        let proposal_tx = monitor.state.psbt_context.payjoin_psbt.unsigned_tx.clone();
        assert!(proposal_tx
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .eq(monitor.contested_prevouts()));

        assert_eq!(monitor.classify_tx(&proposal_tx), Some(SettlementOutcome::Payjoin));
    }

    #[test]
    fn test_classify_tx_fallback() {
        let monitor = segwit_monitor();
        assert_eq!(monitor.classify_tx(&fallback_tx()), Some(SettlementOutcome::Fallback));
    }

    #[test]
    fn test_classify_tx_malleated_fallback() {
        // A third party can change a non-SegWit fallback's script_sig, and with it the txid.
        // It is still the fallback.
        let monitor = segwit_monitor();
        let malleated = with_perturbed_txid(fallback_tx());
        assert_ne!(malleated.compute_txid(), monitor.fallback_tx().compute_txid());

        assert_eq!(monitor.classify_tx(&malleated), Some(SettlementOutcome::Fallback));
    }

    #[test]
    fn test_classify_tx_identical_proposal_is_fallback() {
        // When the proposal is the original, a spend by it is both. It carries no cooperation,
        // so it reports as the fallback.
        let monitor = identical_proposal_monitor();
        assert_eq!(monitor.classify_tx(&fallback_tx()), Some(SettlementOutcome::Fallback));
    }

    #[test]
    fn test_classify_tx_unrecognized() {
        // The sender re-spends its inputs in a transaction that is neither the proposal nor the
        // fallback.
        let monitor = segwit_monitor();
        let other_tx = respent(fallback_tx());

        assert_eq!(monitor.classify_tx(&other_tx), Some(SettlementOutcome::Unrecognized));
    }

    #[test]
    fn test_classify_tx_reordered_outputs_is_unrecognized() {
        // Reordering outputs makes a different transaction. Any signature the receiver made does
        // not cover it, so it is not this session's Payjoin.
        let monitor = cutthrough_monitor();
        let mut reordered_tx = monitor.state.psbt_context.payjoin_psbt.unsigned_tx.clone();
        reordered_tx.output.reverse();

        assert_eq!(monitor.classify_tx(&reordered_tx), Some(SettlementOutcome::Unrecognized));
    }

    #[test]
    fn test_classify_tx_shared_prevouts_are_not_payjoin() {
        // Spending the contested prevouts together with the receiver's contribution does not make
        // a transaction the Payjoin. Only the proposal itself is.
        let monitor = segwit_monitor();
        let other_tx = respent(PARSED_PAYJOIN_PROPOSAL.clone().unsigned_tx);
        assert_eq!(other_tx.input, PARSED_PAYJOIN_PROPOSAL.unsigned_tx.input);

        assert_eq!(monitor.classify_tx(&other_tx), Some(SettlementOutcome::Unrecognized));
    }

    #[test]
    fn test_classify_tx_before_proposal() {
        // Before a proposal exists the sender can only broadcast the fallback or re-spend its
        // inputs. A transaction matching what later becomes the proposal is not yet a Payjoin.
        let receiver = Receiver {
            state: maybe_inputs_owned_v2_from_test_vector(),
            session_context: SHARED_CONTEXT.clone(),
        };
        assert_eq!(receiver.classify_tx(&fallback_tx()), Some(SettlementOutcome::Fallback));
        assert_eq!(
            receiver.classify_tx(&respent(fallback_tx())),
            Some(SettlementOutcome::Unrecognized)
        );
        assert_eq!(
            receiver.classify_tx(&PARSED_PAYJOIN_PROPOSAL.unsigned_tx),
            Some(SettlementOutcome::Unrecognized)
        );
    }

    #[test]
    fn test_classify_tx_payjoin_proposal() {
        // The sender may hold a proposal whose post succeeded before the session left this state.
        let receiver = Receiver {
            state: PayjoinProposal {
                psbt_context: PsbtContext {
                    original_psbt: PARSED_ORIGINAL_PSBT.clone(),
                    payjoin_psbt: PARSED_PAYJOIN_PROPOSAL.clone(),
                },
            },
            session_context: SHARED_CONTEXT.clone(),
        };
        assert_eq!(
            receiver.classify_tx(&PARSED_PAYJOIN_PROPOSAL.unsigned_tx),
            Some(SettlementOutcome::Payjoin)
        );
        assert_eq!(receiver.classify_tx(&fallback_tx()), Some(SettlementOutcome::Fallback));
    }

    #[test]
    fn test_monitor_close_records_no_settlement_outcome() {
        // Closing says the wallet settled the outcome. Whichever verdict classify_tx returned, the
        // log records the protocol handoff and nothing a reorg could falsify.
        let persister = InMemoryPersister::default();

        segwit_monitor().close().save(&persister).expect("InMemoryPersister shouldn't fail");

        let inner = persister.inner.lock().expect("Shouldn't be poisoned");
        assert!(inner.is_closed, "close must close the session");
        assert_eq!(
            inner.events.last(),
            Some(&SessionEvent::Closed(SessionOutcome::PayjoinProposalSent))
        );
    }

    #[test]
    fn test_monitor_mailbox_expiration() {
        let expiration_secs = 1_720_547_781;
        let mut monitor = segwit_monitor();
        monitor.session_context.expiration =
            Time::from_unix_seconds(expiration_secs).expect("valid timestamp");

        assert_eq!(
            monitor.mailbox_expiration(),
            std::time::UNIX_EPOCH + Duration::from_secs(expiration_secs.into())
        );
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
