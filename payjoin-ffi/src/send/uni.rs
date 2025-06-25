use std::sync::{Arc, RwLock};

use bitcoin_ffi::Psbt;

use crate::{error::ForeignError, Url};
use crate::send::error::{SenderPersistedError, SenderReplayError};
pub use crate::send::{
    BuildSenderError, CreateRequestError, EncapsulationError, ResponseError, SerdeJsonError,
};
use crate::{ClientResponse, PjUri, Request};

#[derive(uniffi::Object, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SenderSessionEvent(super::SessionEvent);

impl From<SenderSessionEvent> for super::SessionEvent {
    fn from(value: SenderSessionEvent) -> Self { value.0 }
}

impl From<super::SessionEvent> for SenderSessionEvent {
    fn from(value: super::SessionEvent) -> Self { SenderSessionEvent(value) }
}

#[uniffi::export]
impl SenderSessionEvent {
    pub fn to_json(&self) -> Result<String, SerdeJsonError> {
        serde_json::to_string(&self.0).map_err(Into::into)
    }

    #[uniffi::constructor]
    pub fn from_json(json: String) -> Result<Self, SerdeJsonError> {
        let event: payjoin::send::v2::SessionEvent = serde_json::from_str(&json)?;
        Ok(SenderSessionEvent(event.into()))
    }
}

#[derive(Clone, uniffi::Enum)]
pub enum SenderTypeState {
    Uninitialized,
    WithReplyKey { inner: Arc<WithReplyKey> },
    V2GetContext { inner: Arc<V2GetContext> },
    ProposalReceived { inner: Arc<Psbt> },
    TerminalState,
}

impl From<super::SenderTypeState> for SenderTypeState {
    fn from(value: super::SenderTypeState) -> Self {
        use payjoin::send::v2::SenderTypeState::*;
        match value.0 {
            Uninitialized() => Self::Uninitialized,
            WithReplyKey(inner) =>
                Self::WithReplyKey { inner: Arc::new(super::WithReplyKey::from(inner).into()) },
            V2GetContext(inner) =>
                Self::V2GetContext { inner: Arc::new(super::V2GetContext::from(inner).into()) },
            ProposalReceived(inner) => Self::ProposalReceived { inner: Arc::new(inner.into()) },
            TerminalState => Self::TerminalState,
        }
    }
}

#[derive(uniffi::Object, Clone)]
pub struct SenderSessionHistory(super::SessionHistory);

impl From<super::SessionHistory> for SenderSessionHistory {
    fn from(value: super::SessionHistory) -> Self { Self(value) }
}

impl From<SenderSessionHistory> for super::SessionHistory {
    fn from(value: SenderSessionHistory) -> Self { value.0 }
}

#[uniffi::export]
impl SenderSessionHistory {
    pub fn endpoint(&self) -> Option<Arc<Url>> {
        self.0.0.endpoint().map(|url| Arc::new(url.clone().into()))
    }

    /// Fallback transaction from the session if present
    pub fn fallback_tx(&self) -> Option<Arc<crate::Transaction>> {
        self.0.0.fallback_tx().map(|tx| Arc::new(tx.into()))
    }
}

#[derive(uniffi::Object)]
pub struct SenderReplayResult {
    state: SenderTypeState,
    session_history: SenderSessionHistory,
}

#[uniffi::export]
impl SenderReplayResult {
    pub fn state(&self) -> SenderTypeState { self.state.clone() }

    pub fn session_history(&self) -> SenderSessionHistory { self.session_history.clone() }
}

#[uniffi::export]
pub fn replay_sender_event_log(
    persister: Arc<dyn JsonSenderSessionPersister>,
) -> Result<SenderReplayResult, SenderReplayError> {
    let adapter = CallbackPersisterAdapter::new(persister);
    let (state, session_history) = super::replay_event_log(&adapter).map_err(SenderReplayError::from)?;
    Ok(SenderReplayResult { state: state.into(), session_history: session_history.into() })
}

#[derive(uniffi::Object)]
pub struct InitInputsTransition(super::InitInputsTransition);

#[uniffi::export]
impl InitInputsTransition {
    pub fn save(
        &self,
        persister: Arc<dyn JsonSenderSessionPersister>,
    ) -> Result<WithReplyKey, SenderPersistedError> {
        let adapter = CallbackPersisterAdapter::new(persister);
        let res = self.0.save(&adapter)?;
        Ok(res.into())
    }
}

#[derive(uniffi::Object)]
pub struct SenderBuilder(super::SenderBuilder);

impl From<super::SenderBuilder> for SenderBuilder {
    fn from(value: super::SenderBuilder) -> Self { Self(value) }
}

impl From<SenderBuilder> for super::SenderBuilder {
    fn from(value: SenderBuilder) -> Self { value.0 }
}

#[uniffi::export]
impl SenderBuilder {
    /// Prepare an HTTP request and request context to process the response
    ///
    /// Call [`SenderBuilder::build_recommended()`] or other `build` methods
    /// to create a [`WithReplyKey`]
    #[uniffi::constructor]
    pub fn new(psbt: String, uri: Arc<PjUri>) -> Result<Self, BuildSenderError> {
        super::SenderBuilder::new(psbt, (*uri).clone()).map(Into::into)
    }

    /// Disable output substitution even if the receiver didn't.
    ///
    /// This forbids receiver switching output or decreasing amount.
    /// It is generally **not** recommended to set this as it may prevent the receiver from
    /// doing advanced operations such as opening LN channels and it also guarantees the
    /// receiver will **not** reward the sender with a discount.
    pub fn always_disable_output_substitution(&self) -> Self {
        self.0.always_disable_output_substitution().into()
    }
    // Calculate the recommended fee contribution for an Original PSBT.
    //
    // BIP 78 recommends contributing `originalPSBTFeeRate * vsize(sender_input_type)`.
    // The minfeerate parameter is set if the contribution is available in change.
    //
    // This method fails if no recommendation can be made or if the PSBT is malformed.
    pub fn build_recommended(&self, min_fee_rate: u64) -> InitInputsTransition {
        InitInputsTransition(self.0.build_recommended(min_fee_rate))
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
    ) -> InitInputsTransition {
        InitInputsTransition(self.0.build_with_additional_fee(
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
    pub fn build_non_incentivizing(&self, min_fee_rate: u64) -> InitInputsTransition {
        InitInputsTransition(self.0.build_non_incentivizing(min_fee_rate))
    }
}

#[derive(Clone, uniffi::Object)]
pub struct WithReplyKey(super::WithReplyKey);

impl From<super::WithReplyKey> for WithReplyKey {
    fn from(value: super::WithReplyKey) -> Self { Self(value) }
}

impl From<WithReplyKey> for super::WithReplyKey {
    fn from(value: WithReplyKey) -> Self { value.0 }
}

#[derive(uniffi::Object)]
pub struct WithReplyKeyTransition(super::WithReplyKeyTransition);

#[uniffi::export]
impl WithReplyKeyTransition {
    pub fn save(
        &self,
        persister: Arc<dyn JsonSenderSessionPersister>,
    ) -> Result<V2GetContext, SenderPersistedError> {
        let adapter = CallbackPersisterAdapter::new(persister);
        let res = self.0.save(&adapter)?;
        Ok(res.into())
    }
}

#[uniffi::export]
impl WithReplyKey {
    pub fn extract_v1(&self) -> RequestV1Context {
        let (req, ctx) = self.0.extract_v1();
        RequestV1Context { request: req, context: Arc::new(ctx.into()) }
    }

    /// Extract serialized Request and Context from a Payjoin Proposal.
    ///
    /// This method requires the `rs` pubkey to be extracted from the endpoint
    /// and has no fallback to v1.
    pub fn extract_v2(
        &self,
        ohttp_relay_url: String,
    ) -> Result<RequestV2PostContext, CreateRequestError> {
        match self.0.extract_v2(ohttp_relay_url) {
            Ok((req, ctx)) =>
                Ok(RequestV2PostContext { request: req, context: Arc::new(ctx.into()) }),
            Err(e) => Err(e),
        }
    }

    /// Decodes and validates the response.
    /// Call this method with response from receiver to continue BIP-??? flow. A successful response can either be None if the relay has not response yet or Some(Psbt).
    /// If the response is some valid PSBT you should sign and broadcast.
    pub fn process_response(
        &self,
        response: &[u8],
        post_ctx: &V2PostContext,
    ) -> WithReplyKeyTransition {
        let mut guard = post_ctx.0.write().expect("Lock should not be poisoned");
        let post_ctx = guard.take().expect("Value should not be taken");
        WithReplyKeyTransition(self.0.process_response(response, post_ctx.into()))
    }

    pub fn to_json(&self) -> Result<String, SerdeJsonError> { self.0.to_json() }

    #[uniffi::constructor]
    pub fn from_json(json: &str) -> Result<Self, SerdeJsonError> {
        super::WithReplyKey::from_json(json).map(Into::into)
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

///Data required for validation of response.
/// This type is used to process the response. Get it from SenderBuilder's build methods. Then you only need to call .process_response() on it to continue BIP78 flow.
#[derive(Clone, uniffi::Object)]
pub struct V1Context(super::V1Context);

impl From<super::V1Context> for V1Context {
    fn from(value: super::V1Context) -> Self { Self(value) }
}

#[uniffi::export]
impl V1Context {
    /// Decodes and validates the response.
    /// Call this method with response from receiver to continue BIP78 flow. If the response is valid you will get appropriate PSBT that you should sign and broadcast.
    pub fn process_response(&self, response: &[u8]) -> Result<String, ResponseError> {
        self.0.process_response(response)
    }
}

#[derive(uniffi::Object)]
pub struct V2PostContext(Arc<RwLock<Option<super::V2PostContext>>>);

impl From<super::V2PostContext> for V2PostContext {
    fn from(value: super::V2PostContext) -> Self { Self(Arc::new(RwLock::new(Some(value)))) }
}

#[derive(uniffi::Record)]
pub struct RequestOhttpContext {
    pub request: crate::Request,
    pub ohttp_ctx: Arc<crate::ClientResponse>,
}

#[derive(uniffi::Object)]
pub struct V2GetContextTransitionOutcome(super::V2GetContextTransitionOutcome);

impl From<super::V2GetContextTransitionOutcome> for V2GetContextTransitionOutcome {
    fn from(value: super::V2GetContextTransitionOutcome) -> Self { Self(value) }
}

#[uniffi::export]
impl V2GetContextTransitionOutcome {
    pub fn is_none(&self) -> bool { self.0.is_none() }

    pub fn is_success(&self) -> bool { self.0.is_success() }

    pub fn success(&self) -> Option<Arc<Psbt>> {
        self.0.success().map(|p| p.into())
    }
}

#[derive(uniffi::Object)]
pub struct V2GetContextTransition(super::V2GetContextTransition);

#[uniffi::export]
impl V2GetContextTransition {
    pub fn save(
        &self,
        persister: Arc<dyn JsonSenderSessionPersister>,
    ) -> Result<V2GetContextTransitionOutcome, SenderPersistedError> {
        let adapter = CallbackPersisterAdapter::new(persister);
        let res = self.0.save(&adapter)?;
        Ok(res.into())
    }
}

#[derive(uniffi::Object)]
pub struct V2GetContext(super::V2GetContext);

impl From<super::V2GetContext> for V2GetContext {
    fn from(value: super::V2GetContext) -> Self { Self(value) }
}

#[uniffi::export]
impl V2GetContext {
    pub fn extract_req(
        &self,
        ohttp_relay: String,
    ) -> Result<RequestOhttpContext, CreateRequestError> {
        self.0
            .extract_req(ohttp_relay)
            .map(|(request, ctx)| RequestOhttpContext { request, ohttp_ctx: Arc::new(ctx) })
    }

    /// Decodes and validates the response.
    /// Call this method with response from receiver to continue BIP-??? flow. A successful response can either be None if the relay has not response yet or Some(Psbt).
    /// If the response is some valid PSBT you should sign and broadcast.
    pub fn process_response(
        &self,
        response: &[u8],
        ohttp_ctx: Arc<ClientResponse>,
    ) -> V2GetContextTransition {
        V2GetContextTransition(self.0.process_response(response, ohttp_ctx.as_ref()))
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

    fn save_event(&self, event: &Self::SessionEvent) -> Result<(), Self::InternalStorageError> {
        let super_event: super::SessionEvent = event.clone().into();
        let uni_event: SenderSessionEvent = super_event.into();
        self.callback_persister
            .save(uni_event.to_json().map_err(|e| ForeignError::InternalError(e.to_string()))?)
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
                        .map(|e| e.0.into())
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
