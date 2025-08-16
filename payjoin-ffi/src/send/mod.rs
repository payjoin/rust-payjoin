use std::str::FromStr;
use std::sync::{Arc, RwLock};

use bitcoin_ffi::Psbt;
pub use error::{BuildSenderError, CreateRequestError, EncapsulationError, ResponseError};

use crate::error::ForeignError;
pub use crate::error::{ImplementationError, SerdeJsonError};
use crate::ohttp::ClientResponse;
use crate::request::Request;
use crate::send::error::{SenderPersistedError, SenderReplayError};
use crate::uri::PjUri;
use crate::Url;

pub mod error;

macro_rules! impl_save_for_transition {
    ($ty:ident, $next_state:ident) => {
        #[uniffi::export]
        impl $ty {
            pub fn save(
                &self,
                persister: Arc<dyn JsonSenderSessionPersister>,
            ) -> Result<$next_state, SenderPersistedError> {
                let adapter = CallbackPersisterAdapter::new(persister);
                let mut inner = self.0.write().map_err(|_| {
                    SenderPersistedError::Storage(Arc::new(ImplementationError::from(
                        "Lock poisoned".to_string(),
                    )))
                })?;

                let value = inner.take().ok_or_else(|| {
                    SenderPersistedError::Storage(Arc::new(ImplementationError::from(
                        "Already saved or moved".to_string(),
                    )))
                })?;

                let res = value.save(&adapter).map_err(SenderPersistedError::from)?;
                Ok(res.into())
            }
        }
    };
}

#[derive(uniffi::Object, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SenderSessionEvent(payjoin::send::v2::SessionEvent);

impl From<SenderSessionEvent> for payjoin::send::v2::SessionEvent {
    fn from(value: SenderSessionEvent) -> Self { value.0 }
}

impl From<payjoin::send::v2::SessionEvent> for SenderSessionEvent {
    fn from(value: payjoin::send::v2::SessionEvent) -> Self { SenderSessionEvent(value) }
}

#[uniffi::export]
impl SenderSessionEvent {
    pub fn to_json(&self) -> Result<String, SerdeJsonError> {
        serde_json::to_string(&self.0).map_err(Into::into)
    }

    #[uniffi::constructor]
    pub fn from_json(json: String) -> Result<Self, SerdeJsonError> {
        let event: payjoin::send::v2::SessionEvent = serde_json::from_str(&json)?;
        Ok(SenderSessionEvent(event))
    }
}

#[derive(Clone, uniffi::Enum)]
pub enum SendSession {
    Uninitialized,
    WithReplyKey { inner: Arc<WithReplyKey> },
    V2GetContext { inner: Arc<V2GetContext> },
    ProposalReceived { inner: Arc<Psbt> },
    TerminalFailure,
}

impl From<payjoin::send::v2::SendSession> for SendSession {
    fn from(value: payjoin::send::v2::SendSession) -> Self {
        use payjoin::send::v2::SendSession;
        match value {
            SendSession::Uninitialized => Self::Uninitialized,
            SendSession::WithReplyKey(inner) =>
                Self::WithReplyKey { inner: Arc::new(inner.into()) },
            SendSession::V2GetContext(inner) =>
                Self::V2GetContext { inner: Arc::new(inner.into()) },
            SendSession::ProposalReceived(inner) =>
                Self::ProposalReceived { inner: Arc::new(inner.into()) },
            SendSession::TerminalFailure => Self::TerminalFailure,
        }
    }
}

#[derive(uniffi::Object)]
pub struct SenderReplayResult {
    state: SendSession,
    session_history: SenderSessionHistory,
}

#[uniffi::export]
impl SenderReplayResult {
    pub fn state(&self) -> SendSession { self.state.clone() }

    pub fn session_history(&self) -> SenderSessionHistory { self.session_history.clone() }
}

#[uniffi::export]
pub fn replay_sender_event_log(
    persister: Arc<dyn JsonSenderSessionPersister>,
) -> Result<SenderReplayResult, SenderReplayError> {
    let adapter = CallbackPersisterAdapter::new(persister);
    let (state, session_history) = payjoin::send::v2::replay_event_log(&adapter)?;
    Ok(SenderReplayResult { state: state.into(), session_history: session_history.into() })
}

#[derive(uniffi::Object, Default, Clone)]
pub struct SenderSessionHistory(pub payjoin::send::v2::SessionHistory);

impl From<payjoin::send::v2::SessionHistory> for SenderSessionHistory {
    fn from(value: payjoin::send::v2::SessionHistory) -> Self { Self(value) }
}

impl From<SenderSessionHistory> for payjoin::send::v2::SessionHistory {
    fn from(value: SenderSessionHistory) -> Self { value.0 }
}

#[uniffi::export]
impl SenderSessionHistory {
    pub fn endpoint(&self) -> Option<Arc<Url>> {
        self.0.endpoint().map(|url| Arc::new(url.clone().into()))
    }

    /// Fallback transaction from the session if present
    pub fn fallback_tx(&self) -> Option<Arc<crate::Transaction>> {
        self.0.fallback_tx().map(|tx| Arc::new(tx.into()))
    }
}

#[derive(uniffi::Object)]
#[allow(clippy::type_complexity)]
pub struct InitialSendTransition(
    Arc<
        RwLock<
            Option<
                payjoin::persist::MaybeBadInitInputsTransition<
                    payjoin::send::v2::SessionEvent,
                    payjoin::send::v2::Sender<payjoin::send::v2::WithReplyKey>,
                    payjoin::send::BuildSenderError,
                >,
            >,
        >,
    >,
);

impl_save_for_transition!(InitialSendTransition, WithReplyKey);

///Builder for sender-side payjoin parameters
///
///These parameters define how client wants to handle Payjoin.
#[derive(Clone, uniffi::Object)]
pub struct SenderBuilder(payjoin::send::v2::SenderBuilder);

impl From<payjoin::send::v2::SenderBuilder> for SenderBuilder {
    fn from(value: payjoin::send::v2::SenderBuilder) -> Self { Self(value) }
}

#[uniffi::export]
impl SenderBuilder {
    /// Prepare an HTTP request and request context to process the response
    ///
    /// Call [`SenderBuilder::build_recommended()`] or other `build` methods
    /// to create a [`WithReplyKey`]
    #[uniffi::constructor]
    pub fn new(psbt: String, uri: Arc<PjUri>) -> Result<Self, BuildSenderError> {
        let psbt = payjoin::bitcoin::psbt::Psbt::from_str(psbt.as_str())?;
        Ok(payjoin::send::v2::SenderBuilder::new(psbt, (*uri).clone().into()).into())
    }

    /// Disable output substitution even if the receiver didn't.
    ///
    /// This forbids receiver switching output or decreasing amount.
    /// It is generally **not** recommended to set this as it may prevent the receiver from
    /// doing advanced operations such as opening LN channels and it also guarantees the
    /// receiver will **not** reward the sender with a discount.
    pub fn always_disable_output_substitution(&self) -> Self {
        self.0.clone().always_disable_output_substitution().into()
    }
    // Calculate the recommended fee contribution for an Original PSBT.
    //
    // BIP 78 recommends contributing `originalPSBTFeeRate * vsize(sender_input_type)`.
    // The minfeerate parameter is set if the contribution is available in change.
    //
    // This method fails if no recommendation can be made or if the PSBT is malformed.
    pub fn build_recommended(&self, min_fee_rate: u64) -> InitialSendTransition {
        InitialSendTransition(Arc::new(RwLock::new(Some(
            self.0
                .clone()
                .build_recommended(payjoin::bitcoin::FeeRate::from_sat_per_kwu(min_fee_rate)),
        ))))
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
        &self,
        max_fee_contribution: u64,
        change_index: Option<u8>,
        min_fee_rate: u64,
        clamp_fee_contribution: bool,
    ) -> InitialSendTransition {
        InitialSendTransition(Arc::new(RwLock::new(Some(
            self.0.clone().build_with_additional_fee(
                payjoin::bitcoin::Amount::from_sat(max_fee_contribution),
                change_index.map(|x| x as usize),
                payjoin::bitcoin::FeeRate::from_sat_per_kwu(min_fee_rate),
                clamp_fee_contribution,
            ),
        ))))
    }
    /// Perform Payjoin without incentivizing the payee to cooperate.
    ///
    /// While it's generally better to offer some contribution some users may wish not to.
    /// This function disables contribution.
    pub fn build_non_incentivizing(&self, min_fee_rate: u64) -> InitialSendTransition {
        InitialSendTransition(Arc::new(RwLock::new(Some(
            self.0
                .clone()
                .build_non_incentivizing(payjoin::bitcoin::FeeRate::from_sat_per_kwu(min_fee_rate)),
        ))))
    }
}

#[derive(Clone, uniffi::Object)]
pub struct WithReplyKey(payjoin::send::v2::Sender<payjoin::send::v2::WithReplyKey>);

impl From<payjoin::send::v2::Sender<payjoin::send::v2::WithReplyKey>> for WithReplyKey {
    fn from(value: payjoin::send::v2::Sender<payjoin::send::v2::WithReplyKey>) -> Self {
        Self(value)
    }
}

impl From<WithReplyKey> for payjoin::send::v2::Sender<payjoin::send::v2::WithReplyKey> {
    fn from(value: WithReplyKey) -> Self { value.0 }
}

#[derive(uniffi::Object)]
#[allow(clippy::type_complexity)]
pub struct WithReplyKeyTransition(
    Arc<
        RwLock<
            Option<
                payjoin::persist::MaybeFatalTransition<
                    payjoin::send::v2::SessionEvent,
                    payjoin::send::v2::Sender<payjoin::send::v2::V2GetContext>,
                    payjoin::send::v2::EncapsulationError,
                >,
            >,
        >,
    >,
);

#[uniffi::export]
impl WithReplyKeyTransition {
    pub fn save(
        &self,
        persister: Arc<dyn JsonSenderSessionPersister>,
    ) -> Result<V2GetContext, SenderPersistedError> {
        let adapter = CallbackPersisterAdapter::new(persister);
        let mut inner = self.0.write().map_err(|_| {
            SenderPersistedError::Storage(Arc::new(ImplementationError::from(
                "Lock poisoned".to_string(),
            )))
        })?;

        let value = inner.take().ok_or_else(|| {
            SenderPersistedError::Storage(Arc::new(ImplementationError::from(
                "Already saved or moved".to_string(),
            )))
        })?;

        let res = value.save(&adapter).map_err(SenderPersistedError::from)?;
        Ok(res.into())
    }
}

#[uniffi::export]
impl WithReplyKey {
    pub fn create_v1_post_request(&self) -> RequestV1Context {
        let (req, ctx) = self.0.clone().create_v1_post_request();
        RequestV1Context { request: req.into(), context: Arc::new(ctx.into()) }
    }

    /// Construct serialized Request and Context from a Payjoin Proposal.
    ///
    /// Important: This request must not be retried or reused on failure.
    /// Retransmitting the same ciphertext breaks OHTTP privacy properties.
    /// The specific concern is that the relay can see that a request is being retried.
    pub fn create_v2_post_request(
        &self,
        ohttp_relay: String,
    ) -> Result<RequestV2PostContext, CreateRequestError> {
        match self.0.create_v2_post_request(ohttp_relay) {
            Ok((req, ctx)) =>
                Ok(RequestV2PostContext { request: req.into(), context: Arc::new(ctx.into()) }),
            Err(e) => Err(e.into()),
        }
    }

    /// Decodes and validates the response.
    /// Call this method with response from receiver to continue BIP-??? flow. A successful response can either be None if the relay has not response yet or Some(Psbt).
    /// If the response is some valid PSBT you should sign and broadcast.
    pub fn process_response(
        &self,
        response: &[u8],
        post_ctx: Arc<V2PostContext>,
    ) -> WithReplyKeyTransition {
        let mut guard = post_ctx.0.write().expect("Lock should not be poisoned");
        let post_ctx = guard.take().expect("Value should not be taken");
        WithReplyKeyTransition(Arc::new(RwLock::new(Some(
            self.clone().0.process_response(response, post_ctx),
        ))))
    }
}

#[derive(uniffi::Record)]
pub struct RequestV2PostContext {
    pub request: Request,
    pub context: Arc<V2PostContext>,
}

#[derive(uniffi::Record)]
pub struct RequestV1Context {
    pub request: Request,
    pub context: Arc<V1Context>,
}

/// Data required for validation of response.
/// This type is used to process the response. Get it from SenderBuilder's build methods. Then you only need to call .process_response() on it to continue BIP78 flow.
#[derive(Clone, uniffi::Object)]
pub struct V1Context(Arc<payjoin::send::V1Context>);
impl From<payjoin::send::V1Context> for V1Context {
    fn from(value: payjoin::send::V1Context) -> Self { Self(Arc::new(value)) }
}

#[uniffi::export]
impl V1Context {
    ///Decodes and validates the response.
    /// Call this method with response from receiver to continue BIP78 flow. If the response is valid you will get appropriate PSBT that you should sign and broadcast.
    pub fn process_response(&self, response: &[u8]) -> Result<String, ResponseError> {
        <payjoin::send::V1Context as Clone>::clone(&self.0.clone())
            .process_response(response)
            .map(|e| e.to_string())
            .map_err(Into::into)
    }
}

#[derive(uniffi::Object)]
pub struct V2PostContext(Arc<RwLock<Option<payjoin::send::v2::V2PostContext>>>);

impl From<payjoin::send::v2::V2PostContext> for V2PostContext {
    fn from(value: payjoin::send::v2::V2PostContext) -> Self {
        Self(Arc::new(RwLock::new(Some(value))))
    }
}

#[derive(uniffi::Record)]
pub struct RequestOhttpContext {
    pub request: crate::Request,
    pub ohttp_ctx: Arc<crate::ClientResponse>,
}

#[derive(uniffi::Object)]
pub struct V2GetContext(payjoin::send::v2::Sender<payjoin::send::v2::V2GetContext>);

impl From<payjoin::send::v2::Sender<payjoin::send::v2::V2GetContext>> for V2GetContext {
    fn from(value: payjoin::send::v2::Sender<payjoin::send::v2::V2GetContext>) -> Self {
        Self(value)
    }
}

#[derive(uniffi::Object)]
pub struct V2GetContextTransitionOutcome(
    payjoin::persist::OptionalTransitionOutcome<
        payjoin::bitcoin::Psbt,
        payjoin::send::v2::Sender<payjoin::send::v2::V2GetContext>,
    >,
);

#[uniffi::export]
impl V2GetContextTransitionOutcome {
    pub fn is_none(&self) -> bool { self.0.is_none() }

    pub fn is_success(&self) -> bool { self.0.is_success() }

    pub fn success(&self) -> Option<Arc<Psbt>> {
        self.0.success().map(|r| Arc::new(r.clone().into()))
    }
}

impl
    From<
        payjoin::persist::OptionalTransitionOutcome<
            payjoin::bitcoin::Psbt,
            payjoin::send::v2::Sender<payjoin::send::v2::V2GetContext>,
        >,
    > for V2GetContextTransitionOutcome
{
    fn from(
        value: payjoin::persist::OptionalTransitionOutcome<
            payjoin::bitcoin::Psbt,
            payjoin::send::v2::Sender<payjoin::send::v2::V2GetContext>,
        >,
    ) -> Self {
        Self(value)
    }
}

#[derive(uniffi::Object)]
#[allow(clippy::type_complexity)]
pub struct V2GetContextTransition(
    Arc<
        RwLock<
            Option<
                payjoin::persist::MaybeSuccessTransitionWithNoResults<
                    payjoin::send::v2::SessionEvent,
                    payjoin::bitcoin::Psbt,
                    payjoin::send::v2::Sender<payjoin::send::v2::V2GetContext>,
                    payjoin::send::ResponseError,
                >,
            >,
        >,
    >,
);

impl_save_for_transition!(V2GetContextTransition, V2GetContextTransitionOutcome);

#[uniffi::export]
impl V2GetContext {
    pub fn create_poll_request(
        &self,
        ohttp_relay: String,
    ) -> Result<RequestOhttpContext, CreateRequestError> {
        self.0
            .create_poll_request(ohttp_relay)
            .map(|(req, ctx)| RequestOhttpContext {
                request: req.into(),
                ohttp_ctx: Arc::new(ctx.into()),
            })
            .map_err(|e| e.into())
    }

    /// Decodes and validates the response.
    /// Call this method with response from receiver to continue BIP-??? flow. A successful response can either be None if the relay has not response yet or Some(Psbt).
    /// If the response is some valid PSBT you should sign and broadcast.
    pub fn process_response(
        &self,
        response: &[u8],
        ohttp_ctx: &ClientResponse,
    ) -> V2GetContextTransition {
        V2GetContextTransition(Arc::new(RwLock::new(Some(
            self.0.process_response(response, ohttp_ctx.into()),
        ))))
    }
}

/// Session persister that should save and load events as JSON strings.
#[uniffi::export(with_foreign)]
pub trait JsonSenderSessionPersister: Send + Sync {
    fn save(&self, event: String) -> Result<(), ForeignError>;
    fn load(&self) -> Result<Vec<String>, ForeignError>;
    fn close(&self) -> Result<(), ForeignError>;
}

// The adapter to use the save and load callbacks
#[derive(Clone)]
struct CallbackPersisterAdapter {
    callback_persister: Arc<dyn JsonSenderSessionPersister>,
}

impl CallbackPersisterAdapter {
    pub fn new(callback_persister: Arc<dyn JsonSenderSessionPersister>) -> Self {
        Self { callback_persister }
    }
}

// Implement the Persister trait for the adapter
impl payjoin::persist::SessionPersister for CallbackPersisterAdapter {
    type SessionEvent = payjoin::send::v2::SessionEvent;
    type InternalStorageError = ForeignError;

    fn save_event(&self, event: Self::SessionEvent) -> Result<(), Self::InternalStorageError> {
        let event: SenderSessionEvent = event.into();
        self.callback_persister
            .save(event.to_json().map_err(|e| ForeignError::InternalError(e.to_string()))?)
    }

    fn load(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Self::SessionEvent>>, Self::InternalStorageError> {
        let res = self.callback_persister.load()?;
        Ok(Box::new(
            match res
                .into_iter()
                .map(|event| {
                    SenderSessionEvent::from_json(event)
                        .map_err(|e| ForeignError::InternalError(e.to_string()))
                        .map(|e| e.into())
                })
                .collect::<Result<Vec<_>, _>>()
            {
                Ok(events) => Box::new(events.into_iter()),
                Err(e) => return Err(e),
            },
        ))
    }

    fn close(&self) -> Result<(), Self::InternalStorageError> { self.callback_persister.close() }
}
