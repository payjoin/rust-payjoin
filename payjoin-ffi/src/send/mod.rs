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
                let mut inner = self.0.write().expect("Lock should not be poisoned");

                let value = inner.take().expect("Already saved or moved");

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

#[derive(Clone, uniffi::Object)]
pub struct SenderSessionOutcome {
    inner: payjoin::send::v2::SessionOutcome,
}

impl From<payjoin::send::v2::SessionOutcome> for SenderSessionOutcome {
    fn from(value: payjoin::send::v2::SessionOutcome) -> Self { Self { inner: value } }
}

impl From<SenderSessionOutcome> for payjoin::send::v2::SessionOutcome {
    fn from(value: SenderSessionOutcome) -> Self { value.inner }
}

#[derive(Clone, uniffi::Enum)]
pub enum SendSession {
    WithReplyKey { inner: Arc<WithReplyKey> },
    PollingForProposal { inner: Arc<PollingForProposal> },
    ProposalReceived { inner: Arc<Psbt> },
    Closed { inner: Arc<SenderSessionOutcome> },
}

impl From<payjoin::send::v2::SendSession> for SendSession {
    fn from(value: payjoin::send::v2::SendSession) -> Self {
        use payjoin::send::v2::SendSession;
        match value {
            SendSession::WithReplyKey(inner) =>
                Self::WithReplyKey { inner: Arc::new(inner.into()) },
            SendSession::PollingForProposal(inner) =>
                Self::PollingForProposal { inner: Arc::new(inner.into()) },
            SendSession::ProposalReceived(inner) =>
                Self::ProposalReceived { inner: Arc::new(inner.into()) },
            SendSession::Closed(session_outcome) =>
                Self::Closed { inner: Arc::new(session_outcome.into()) },
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

#[derive(uniffi::Object, Clone)]
pub struct SenderSessionHistory(pub payjoin::send::v2::SessionHistory);

impl From<payjoin::send::v2::SessionHistory> for SenderSessionHistory {
    fn from(value: payjoin::send::v2::SessionHistory) -> Self { Self(value) }
}

impl From<SenderSessionHistory> for payjoin::send::v2::SessionHistory {
    fn from(value: SenderSessionHistory) -> Self { value.0 }
}

#[uniffi::export]
impl SenderSessionHistory {
    /// Fallback transaction from the session if present
    pub fn fallback_tx(&self) -> Arc<crate::Transaction> { Arc::new(self.0.fallback_tx().into()) }
}

#[derive(uniffi::Object)]
#[allow(clippy::type_complexity)]
pub struct InitialSendTransition(
    Arc<
        RwLock<
            Option<
                payjoin::persist::NextStateTransition<
                    payjoin::send::v2::SessionEvent,
                    payjoin::send::v2::Sender<payjoin::send::v2::WithReplyKey>,
                >,
            >,
        >,
    >,
);

#[uniffi::export]
impl InitialSendTransition {
    pub fn save(
        &self,
        persister: Arc<dyn JsonSenderSessionPersister>,
    ) -> Result<WithReplyKey, ForeignError> {
        let adapter = CallbackPersisterAdapter::new(persister);
        let mut inner = self.0.write().expect("Lock should not be poisoned");

        let value = inner.take().expect("Already saved or moved");

        let res = value.save(&adapter).map_err(|e| ForeignError::InternalError(e.to_string()))?;
        Ok(res.into())
    }
}

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
        Ok(payjoin::send::v2::SenderBuilder::new(psbt, Arc::unwrap_or_clone(uri).into()).into())
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
    pub fn build_recommended(
        &self,
        min_fee_rate: u64,
    ) -> Result<InitialSendTransition, BuildSenderError> {
        self.0
            .clone()
            .build_recommended(payjoin::bitcoin::FeeRate::from_sat_per_kwu(min_fee_rate))
            .map(|transition| InitialSendTransition(Arc::new(RwLock::new(Some(transition)))))
            .map_err(BuildSenderError::from)
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
    ) -> Result<InitialSendTransition, BuildSenderError> {
        self.0
            .clone()
            .build_with_additional_fee(
                payjoin::bitcoin::Amount::from_sat(max_fee_contribution),
                change_index.map(|x| x as usize),
                payjoin::bitcoin::FeeRate::from_sat_per_kwu(min_fee_rate),
                clamp_fee_contribution,
            )
            .map(|transition| InitialSendTransition(Arc::new(RwLock::new(Some(transition)))))
            .map_err(BuildSenderError::from)
    }
    /// Perform Payjoin without incentivizing the payee to cooperate.
    ///
    /// While it's generally better to offer some contribution some users may wish not to.
    /// This function disables contribution.
    pub fn build_non_incentivizing(
        &self,
        min_fee_rate: u64,
    ) -> Result<InitialSendTransition, BuildSenderError> {
        self.0
            .clone()
            .build_non_incentivizing(payjoin::bitcoin::FeeRate::from_sat_per_kwu(min_fee_rate))
            .map(|transition| InitialSendTransition(Arc::new(RwLock::new(Some(transition)))))
            .map_err(BuildSenderError::from)
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
                    payjoin::send::v2::Sender<payjoin::send::v2::PollingForProposal>,
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
    ) -> Result<PollingForProposal, SenderPersistedError> {
        let adapter = CallbackPersisterAdapter::new(persister);
        let mut inner = self.0.write().expect("Lock should not be poisoned");

        let value = inner.take().expect("Already saved or moved");

        let res = value.save(&adapter).map_err(SenderPersistedError::from)?;
        Ok(res.into())
    }
}

#[uniffi::export]
impl WithReplyKey {
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
pub struct V1Context(Arc<payjoin::send::v1::V1Context>);
impl From<payjoin::send::v1::V1Context> for V1Context {
    fn from(value: payjoin::send::v1::V1Context) -> Self { Self(Arc::new(value)) }
}

#[uniffi::export]
impl V1Context {
    ///Decodes and validates the response.
    /// Call this method with response from receiver to continue BIP78 flow. If the response is valid you will get appropriate PSBT that you should sign and broadcast.
    pub fn process_response(&self, response: &[u8]) -> Result<String, ResponseError> {
        <payjoin::send::v1::V1Context as Clone>::clone(&self.0.clone())
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
pub struct PollingForProposal(payjoin::send::v2::Sender<payjoin::send::v2::PollingForProposal>);

impl From<payjoin::send::v2::Sender<payjoin::send::v2::PollingForProposal>> for PollingForProposal {
    fn from(value: payjoin::send::v2::Sender<payjoin::send::v2::PollingForProposal>) -> Self {
        Self(value)
    }
}

#[derive(uniffi::Enum)]
pub enum PollingForProposalTransitionOutcome {
    Progress { inner: Arc<Psbt> },
    Stasis { inner: Arc<PollingForProposal> },
}

impl
    From<
        payjoin::persist::OptionalTransitionOutcome<
            payjoin::bitcoin::Psbt,
            payjoin::send::v2::Sender<payjoin::send::v2::PollingForProposal>,
        >,
    > for PollingForProposalTransitionOutcome
{
    fn from(
        value: payjoin::persist::OptionalTransitionOutcome<
            payjoin::bitcoin::Psbt,
            payjoin::send::v2::Sender<payjoin::send::v2::PollingForProposal>,
        >,
    ) -> Self {
        match value {
            payjoin::persist::OptionalTransitionOutcome::Progress(psbt) =>
                Self::Progress { inner: Arc::new(psbt.into()) },
            payjoin::persist::OptionalTransitionOutcome::Stasis(state) =>
                Self::Stasis { inner: Arc::new(state.into()) },
        }
    }
}

#[derive(uniffi::Object)]
#[allow(clippy::type_complexity)]
pub struct PollingForProposalTransition(
    Arc<
        RwLock<
            Option<
                payjoin::persist::MaybeSuccessTransitionWithNoResults<
                    payjoin::send::v2::SessionEvent,
                    payjoin::bitcoin::Psbt,
                    payjoin::send::v2::Sender<payjoin::send::v2::PollingForProposal>,
                    payjoin::send::ResponseError,
                >,
            >,
        >,
    >,
);

impl_save_for_transition!(PollingForProposalTransition, PollingForProposalTransitionOutcome);

#[uniffi::export]
impl PollingForProposal {
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
    ) -> PollingForProposalTransition {
        PollingForProposalTransition(Arc::new(RwLock::new(Some(
            self.0.clone().process_response(response, ohttp_ctx.into()),
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
