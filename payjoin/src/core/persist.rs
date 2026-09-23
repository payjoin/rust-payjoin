//! State machine persistence for payjoin sessions.
//!
//! The receiver and sender state machines are driven by events logged
//! through the [`event_log`] crate. This module re-exports that crate's
//! types, with its `Persister` traits under the `SessionPersister` names
//! payjoin exposes. See the [`event_log`] documentation for the
//! compatibility rules events must follow and for how transient errors
//! preserve typestate linearity.

pub use event_log::{
    AcceptNextState, AcceptOptionalTransition, AsyncPersister as AsyncSessionPersister,
    InMemoryAsyncPersister, InMemoryPersister, MaybeFatalOrSuccessTransition, MaybeFatalTransition,
    MaybeFatalTransitionWithNoResults, MaybeSuccessTransitionWithNoResults,
    MaybeTerminalSuccessTransition, MaybeTerminalTransition, MaybeTransientTransition,
    NextStateTransition, OptionalTransitionOutcome, PersistedError, Persister as SessionPersister,
    RejectBadInitInputs, RejectFatal, RejectReplyableError, RejectTransient, Rejection,
    TerminalTransition,
};
