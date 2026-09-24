use std::str::FromStr;
use std::sync::{Arc, RwLock};

pub use error::{
    CreateRequestError, DecapsulationError, PsbtParseError, ResponseError, SenderBuilderError,
    SenderInputError,
};

use crate::error::ForeignError;
pub use crate::error::{ImplementationError, SerdeJsonError};
use crate::ohttp::{ClientResponse, ClientResponseError};
use crate::request::Request;
use crate::send::error::{SenderPersistedError, SenderReplayError};
use crate::uri::PjUri;
use crate::validation::{validate_amount_sat, validate_fee_rate_sat_per_kwu};

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

            pub async fn save_async(
                &self,
                persister: Arc<dyn JsonSenderSessionPersisterAsync>,
            ) -> Result<$next_state, SenderPersistedError> {
                let adapter = AsyncCallbackPersisterAdapter::new(persister);
                // Extract value while holding the lock, then drop the guard before await
                let value = {
                    let mut inner = self.0.write().expect("Lock should not be poisoned");
                    inner.take().expect("Already saved or moved")
                };

                let res = value.save_async(&adapter).await.map_err(SenderPersistedError::from)?;
                Ok(res.into())
            }
        }
    };
}

#[derive(uniffi::Object)]
#[allow(clippy::type_complexity)]
pub struct SenderCancelTransition(
    Arc<
        RwLock<
            Option<
                payjoin::persist::NextStateTransition<
                    payjoin::send::v2::SessionEvent,
                    payjoin::send::v2::Sender<payjoin::send::v2::PendingFallback>,
                >,
            >,
        >,
    >,
);

#[uniffi::export]
impl SenderCancelTransition {
    pub fn save(
        &self,
        persister: Arc<dyn JsonSenderSessionPersister>,
    ) -> Result<SenderPendingFallback, SenderPersistedError> {
        let adapter = CallbackPersisterAdapter::new(persister);
        let mut inner = self.0.write().expect("Lock should not be poisoned");
        let value = inner.take().expect("Already saved or moved");
        let res = value
            .save(&adapter)
            .map_err(|e| SenderPersistedError::from(ImplementationError::new(e)))?;
        Ok(res.into())
    }

    pub async fn save_async(
        &self,
        persister: Arc<dyn JsonSenderSessionPersisterAsync>,
    ) -> Result<SenderPendingFallback, SenderPersistedError> {
        let adapter = AsyncCallbackPersisterAdapter::new(persister);
        let value = {
            let mut inner = self.0.write().expect("Lock should not be poisoned");
            inner.take().expect("Already saved or moved")
        };
        let res = value
            .save_async(&adapter)
            .await
            .map_err(|e| SenderPersistedError::from(ImplementationError::new(e)))?;
        Ok(res.into())
    }
}

macro_rules! impl_cancel_for_sender {
    ($ty:ident) => {
        #[uniffi::export]
        impl $ty {
            /// Cancel the Payjoin session immediately.
            ///
            /// Returns a [`SenderCancelTransition`] that, once persisted, yields a
            /// [`SenderPendingFallback`] state. Call [`SenderPendingFallback::fallback_tx`] to get
            /// the original transaction
            pub fn cancel(&self) -> SenderCancelTransition {
                let transition = self.0.clone().cancel();
                SenderCancelTransition(Arc::new(RwLock::new(Some(transition))))
            }
        }
    };
}

impl_cancel_for_sender!(WithReplyKey);
impl_cancel_for_sender!(PollingForProposal);

#[derive(uniffi::Object, Debug, Clone)]
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
pub struct SenderSessionOutcome(payjoin::send::v2::SessionOutcome);

impl From<payjoin::send::v2::SessionOutcome> for SenderSessionOutcome {
    fn from(value: payjoin::send::v2::SessionOutcome) -> Self { Self(value) }
}

impl From<SenderSessionOutcome> for payjoin::send::v2::SessionOutcome {
    fn from(value: SenderSessionOutcome) -> Self { value.0 }
}

#[uniffi::export]
impl SenderSessionOutcome {
    pub fn is_success(&self) -> bool {
        matches!(self.0, payjoin::send::v2::SessionOutcome::Success(_))
    }

    pub fn success_psbt_base64(&self) -> Option<String> {
        match &self.0 {
            payjoin::send::v2::SessionOutcome::Success(psbt) => Some(psbt.to_string()),
            _ => None,
        }
    }

    pub fn is_aborted(&self) -> bool {
        matches!(self.0, payjoin::send::v2::SessionOutcome::Aborted)
    }
}

#[derive(Clone, uniffi::Enum)]
pub enum SendSession {
    WithReplyKey { inner: Arc<WithReplyKey> },
    PollingForProposal { inner: Arc<PollingForProposal> },
    SenderPendingFallback { inner: Arc<SenderPendingFallback> },
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
            SendSession::PendingFallback(inner) =>
                Self::SenderPendingFallback { inner: Arc::new(inner.into()) },
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

#[uniffi::export]
pub async fn replay_sender_event_log_async(
    persister: Arc<dyn JsonSenderSessionPersisterAsync>,
) -> Result<SenderReplayResult, SenderReplayError> {
    let adapter = AsyncCallbackPersisterAdapter::new(persister);
    let (state, session_history) = payjoin::send::v2::replay_event_log_async(&adapter).await?;
    Ok(SenderReplayResult { state: state.into(), session_history: session_history.into() })
}

/// Represents the status of a session that can be inferred from the information in the session
/// event log.
#[derive(uniffi::Object)]
pub struct SenderSessionStatus {
    inner: payjoin::send::v2::SessionStatus,
}

impl From<payjoin::send::v2::SessionStatus> for SenderSessionStatus {
    fn from(value: payjoin::send::v2::SessionStatus) -> Self { Self { inner: value } }
}

impl From<SenderSessionStatus> for payjoin::send::v2::SessionStatus {
    fn from(value: SenderSessionStatus) -> Self { value.inner }
}

#[derive(uniffi::Object)]
pub struct PjParam(payjoin::uri::v2::PjParam);

impl From<payjoin::uri::v2::PjParam> for PjParam {
    fn from(value: payjoin::uri::v2::PjParam) -> Self { Self(value) }
}

impl From<PjParam> for payjoin::uri::v2::PjParam {
    fn from(value: PjParam) -> Self { value.0 }
}

#[uniffi::export]
impl PjParam {
    /// The receiver's ephemeral HPKE public key, as 33 compressed bytes.
    ///
    /// Stable for the lifetime of a receive session. Consumers use it to
    /// deduplicate and resume sender sessions and to ensure a receiver key
    /// is not reused across sessions, without parsing the endpoint fragment.
    pub fn receiver_pubkey(&self) -> Vec<u8> {
        self.0.receiver_pubkey().to_compressed_bytes().to_vec()
    }
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
    pub fn fallback_tx(&self) -> Vec<u8> {
        payjoin::bitcoin::consensus::encode::serialize(&self.0.fallback_tx())
    }

    pub fn pj_param(&self) -> Arc<PjParam> { Arc::new(self.0.pj_param().to_owned().into()) }

    pub fn status(&self) -> SenderSessionStatus { self.0.status().into() }
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

    pub async fn save_async(
        &self,
        persister: Arc<dyn JsonSenderSessionPersisterAsync>,
    ) -> Result<WithReplyKey, ForeignError> {
        let adapter = AsyncCallbackPersisterAdapter::new(persister);
        let value = {
            let mut inner = self.0.write().expect("Lock should not be poisoned");
            inner.take().expect("Already saved or moved")
        };

        let res = value
            .save_async(&adapter)
            .await
            .map_err(|e| ForeignError::InternalError(e.to_string()))?;
        Ok(res.into())
    }
}

/// Builder for sender-side payjoin parameters
///
/// These parameters define how client wants to handle Payjoin.
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
    ///
    /// Only BIP 77 (v2) payjoin URIs are supported. A URI whose `pj` endpoint is
    /// BIP 78 (v1) only fails with [`SenderInputError::UnsupportedPjVersion`].
    #[uniffi::constructor]
    pub fn new(psbt: String, uri: Arc<PjUri>) -> Result<Self, SenderInputError> {
        let psbt = payjoin::bitcoin::psbt::Psbt::from_str(psbt.as_str())
            .map_err(PsbtParseError::from)
            .map_err(SenderInputError::Psbt)?;
        let uri: payjoin::PjUri = Arc::unwrap_or_clone(uri).into();
        // These bindings expose no v1 sender, so a BIP 78 endpoint is refused up front.
        let builder = match uri.extras().pj_param() {
            payjoin::PjParam::V2(pj_param) => payjoin::send::v2::SenderBuilder::from_parts(
                psbt,
                pj_param,
                uri.address(),
                uri.amount(),
            ),
            _ => return Err(SenderInputError::UnsupportedPjVersion),
        };
        Ok(builder.into())
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
        min_fee_rate_sat_per_kwu: u64,
    ) -> Result<InitialSendTransition, SenderInputError> {
        let fee_rate = validate_fee_rate_sat_per_kwu(min_fee_rate_sat_per_kwu)?;
        self.0
            .clone()
            .build_recommended(fee_rate)
            .map(|transition| InitialSendTransition(Arc::new(RwLock::new(Some(transition)))))
            .map_err(|e: payjoin::send::BuildSenderError| {
                SenderInputError::Build(Arc::new(e.into()))
            })
    }
    /// Offer the receiver contribution to pay for his input.
    ///
    /// These parameters will allow the receiver to take `max_fee_contribution_sats` from given change
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
        max_fee_contribution_sats: u64,
        change_index: Option<u8>,
        min_fee_rate_sat_per_kwu: u64,
        clamp_fee_contribution: bool,
    ) -> Result<InitialSendTransition, SenderInputError> {
        let max_fee_contribution = validate_amount_sat(max_fee_contribution_sats)?;
        let fee_rate = validate_fee_rate_sat_per_kwu(min_fee_rate_sat_per_kwu)?;
        self.0
            .clone()
            .build_with_additional_fee(
                max_fee_contribution,
                change_index.map(|x| x as usize),
                fee_rate,
                clamp_fee_contribution,
            )
            .map(|transition| InitialSendTransition(Arc::new(RwLock::new(Some(transition)))))
            .map_err(|e: payjoin::send::BuildSenderError| {
                SenderInputError::Build(Arc::new(e.into()))
            })
    }
    /// Perform Payjoin without incentivizing the payee to cooperate.
    ///
    /// While it's generally better to offer some contribution some users may wish not to.
    /// This function disables contribution.
    pub fn build_non_incentivizing(
        &self,
        min_fee_rate_sat_per_kwu: u64,
    ) -> Result<InitialSendTransition, SenderInputError> {
        let fee_rate = validate_fee_rate_sat_per_kwu(min_fee_rate_sat_per_kwu)?;
        self.0
            .clone()
            .build_non_incentivizing(fee_rate)
            .map(|transition| InitialSendTransition(Arc::new(RwLock::new(Some(transition)))))
            .map_err(|e: payjoin::send::BuildSenderError| {
                SenderInputError::Build(Arc::new(e.into()))
            })
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
                    payjoin::send::v2::DecapsulationError,
                    (),
                    payjoin::send::v2::Sender<payjoin::send::v2::WithReplyKey>,
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

    pub async fn save_async(
        &self,
        persister: Arc<dyn JsonSenderSessionPersisterAsync>,
    ) -> Result<PollingForProposal, SenderPersistedError> {
        let adapter = AsyncCallbackPersisterAdapter::new(persister);
        let value = {
            let mut inner = self.0.write().expect("Lock should not be poisoned");
            inner.take().expect("Already saved or moved")
        };

        let res = value.save_async(&adapter).await.map_err(SenderPersistedError::from)?;
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
    ) -> Result<RequestOhttpContext, CreateRequestError> {
        match self.0.create_v2_post_request(ohttp_relay) {
            Ok((req, ctx)) =>
                Ok(RequestOhttpContext { request: req.into(), ohttp_ctx: Arc::new(ctx.into()) }),
            Err(e) => Err(e.into()),
        }
    }

    /// Decodes and validates the response.
    /// Call this method with a response from the receiver to continue the BIP77 flow.
    /// A successful response can either be `None` if the relay has no response yet,
    /// or `Some(Psbt)`.
    /// If the response is a valid PSBT you should sign and broadcast it.
    ///
    /// Returns [`ClientResponseError::AlreadyUsed`] if `post_ctx` was already
    /// used to process a response.
    pub fn process_response(
        &self,
        response: &[u8],
        post_ctx: &ClientResponse,
    ) -> Result<WithReplyKeyTransition, ClientResponseError> {
        Ok(WithReplyKeyTransition(Arc::new(RwLock::new(Some(
            self.0.clone().process_response(response, post_ctx.try_into()?),
        )))))
    }
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
    /// Decodes and validates the response.
    /// Call this method with response from receiver to continue BIP78 flow. If the response is valid you will get appropriate PSBT that you should sign and broadcast.
    pub fn process_response(&self, response: &[u8]) -> Result<String, ResponseError> {
        <payjoin::send::v1::V1Context as Clone>::clone(&self.0.clone())
            .process_response(response)
            .map(|e| e.to_string())
            .map_err(Into::into)
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
    Progress { psbt_base64: String },
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
                Self::Progress { psbt_base64: psbt.to_string() },
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
    /// Call this method with a response from the receiver to continue the BIP77 flow.
    /// A successful response can either be `None` if the relay has no response yet,
    /// or `Some(Psbt)`.
    /// If the response is a valid PSBT you should sign and broadcast it.
    ///
    /// Returns [`ClientResponseError::AlreadyUsed`] if `ohttp_ctx` was already
    /// used to process a response.
    pub fn process_response(
        &self,
        response: &[u8],
        ohttp_ctx: &ClientResponse,
    ) -> Result<PollingForProposalTransition, ClientResponseError> {
        Ok(PollingForProposalTransition(Arc::new(RwLock::new(Some(
            self.0.clone().process_response(response, ohttp_ctx.try_into()?),
        )))))
    }
}

#[derive(Clone, uniffi::Object)]
pub struct SenderPendingFallback(payjoin::send::v2::Sender<payjoin::send::v2::PendingFallback>);

impl From<payjoin::send::v2::Sender<payjoin::send::v2::PendingFallback>> for SenderPendingFallback {
    fn from(value: payjoin::send::v2::Sender<payjoin::send::v2::PendingFallback>) -> Self {
        Self(value)
    }
}

#[derive(uniffi::Object)]
#[allow(clippy::type_complexity)]
pub struct BroadcastedTransition(
    Arc<RwLock<Option<payjoin::persist::TerminalTransition<payjoin::send::v2::SessionEvent, ()>>>>,
);

#[uniffi::export]
impl BroadcastedTransition {
    pub fn save(
        &self,
        persister: Arc<dyn JsonSenderSessionPersister>,
    ) -> Result<(), SenderPersistedError> {
        let adapter = CallbackPersisterAdapter::new(persister);
        let mut inner = self.0.write().expect("Lock should not be poisoned");
        let value = inner.take().expect("Already saved or moved");
        value.save(&adapter).map_err(|e| SenderPersistedError::from(ImplementationError::new(e)))
    }

    pub async fn save_async(
        &self,
        persister: Arc<dyn JsonSenderSessionPersisterAsync>,
    ) -> Result<(), SenderPersistedError> {
        let adapter = AsyncCallbackPersisterAdapter::new(persister);
        let value = {
            let mut inner = self.0.write().expect("Lock should not be poisoned");
            inner.take().expect("Already saved or moved")
        };
        value
            .save_async(&adapter)
            .await
            .map_err(|e| SenderPersistedError::from(ImplementationError::new(e)))
    }
}

#[uniffi::export]
impl SenderPendingFallback {
    /// Returns the fallback transaction as consensus-encoded raw bytes.
    ///
    /// This is the sender's original transaction that should be broadcast to
    /// complete the payment without Payjoin.
    pub fn fallback_tx(&self) -> Vec<u8> {
        payjoin::bitcoin::consensus::serialize(self.0.fallback_tx())
    }

    /// Mark the session as complete, signaling that the fallback transaction
    /// has been broadcast or its control has been transferred.
    ///
    /// Persist the returned [`BroadcastedTransition`] to close the session.
    pub fn close(&self) -> BroadcastedTransition {
        BroadcastedTransition(Arc::new(RwLock::new(Some(self.0.close()))))
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
        let events = res
            .into_iter()
            .map(|event| {
                SenderSessionEvent::from_json(event)
                    .map_err(|e| ForeignError::InternalError(e.to_string()))
                    .map(|e| e.into())
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Box::new(events.into_iter()))
    }

    fn close(&self) -> Result<(), Self::InternalStorageError> { self.callback_persister.close() }
}

/// Async session persister that should save and load events as JSON strings.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait JsonSenderSessionPersisterAsync: Send + Sync {
    async fn save(&self, event: String) -> Result<(), ForeignError>;
    async fn load(&self) -> Result<Vec<String>, ForeignError>;
    async fn close(&self) -> Result<(), ForeignError>;
}

/// Adapter for the [JsonSenderSessionPersisterAsync] trait to use the save and load callbacks.
struct AsyncCallbackPersisterAdapter {
    callback_persister: Arc<dyn JsonSenderSessionPersisterAsync>,
}

impl AsyncCallbackPersisterAdapter {
    pub fn new(callback_persister: Arc<dyn JsonSenderSessionPersisterAsync>) -> Self {
        Self { callback_persister }
    }
}

impl payjoin::persist::AsyncSessionPersister for AsyncCallbackPersisterAdapter {
    type SessionEvent = payjoin::send::v2::SessionEvent;
    type InternalStorageError = ForeignError;

    fn save_event(
        &self,
        event: Self::SessionEvent,
    ) -> impl std::future::Future<Output = Result<(), Self::InternalStorageError>> + Send {
        let uni_event: SenderSessionEvent = event.into();
        let persister = self.callback_persister.clone();
        async move {
            let json =
                uni_event.to_json().map_err(|e| ForeignError::InternalError(e.to_string()))?;
            persister.save(json).await
        }
    }

    fn load(
        &self,
    ) -> impl std::future::Future<
        Output = Result<
            Box<dyn Iterator<Item = Self::SessionEvent> + Send>,
            Self::InternalStorageError,
        >,
    > + Send {
        let persister = self.callback_persister.clone();
        async move {
            let res = persister.load().await?;
            let events: Vec<_> = res
                .into_iter()
                .map(|event| {
                    SenderSessionEvent::from_json(event)
                        .map_err(|e| ForeignError::InternalError(e.to_string()))
                        .map(Into::into)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Box::new(events.into_iter()) as Box<dyn Iterator<Item = _> + Send>)
        }
    }

    fn close(
        &self,
    ) -> impl std::future::Future<Output = Result<(), Self::InternalStorageError>> + Send {
        let persister = self.callback_persister.clone();
        async move { persister.close().await }
    }
}

#[cfg(all(test, feature = "_test-utils"))]
mod tests {
    use payjoin_test_utils::ORIGINAL_PSBT;

    use super::*;
    use crate::uri::Uri;

    const V1_PJ_URI: &str =
        "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com";
    const V2_PJ_URI: &str = "bitcoin:2N47mmrWXsNBvQR6k78hWJoTji57zXwNcU7?pjos=0&pj=HTTPS://PAYJO.IN/TXJCGKTKXLUUZ%23EX1WKV8CEC-OH1QYPM59NK2LXXS4890SUAXXYT25Z2VAPHP0X7YEYCJXGWAG6UG9ZU6NQ-RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV";

    // check_pj_supported accepts BIP 78 and BIP 77 endpoints alike, so a v1 URI
    // reaches SenderBuilder::new and the version check has to happen there.
    fn pj_uri(uri: &str) -> Arc<PjUri> {
        Uri::parse(uri.to_string())
            .expect("valid URI")
            .check_pj_supported()
            .expect("payjoin to be supported")
    }

    #[test]
    fn v1_uri_is_rejected_with_typed_error() {
        let err = SenderBuilder::new(ORIGINAL_PSBT.to_string(), pj_uri(V1_PJ_URI))
            .err()
            .expect("v1 URI must be rejected");
        assert!(matches!(err, SenderInputError::UnsupportedPjVersion), "got {err:?}");
    }

    #[test]
    fn v2_uri_is_accepted() {
        SenderBuilder::new(ORIGINAL_PSBT.to_string(), pj_uri(V2_PJ_URI))
            .expect("v2 URI must be accepted");
    }

    #[test]
    fn reusing_ohttp_context_returns_error() {
        use payjoin::persist::InMemoryPersister;
        use payjoin::receive::v2::ReceiverBuilder;
        use payjoin_test_utils::{EXAMPLE_URL, PARSED_ORIGINAL_PSBT};

        let address = payjoin::bitcoin::Address::from_str("2N47mmrWXsNBvQR6k78hWJoTji57zXwNcU7")
            .expect("valid address")
            .assume_checked();
        let ohttp_keys = payjoin::OhttpKeys::decode(&payjoin_test_utils::ohttp_key_config_bytes())
            .expect("valid ohttp keys");
        let pj_uri = ReceiverBuilder::new(address, EXAMPLE_URL, ohttp_keys)
            .expect("valid receiver builder")
            .build()
            .save(&InMemoryPersister::default())
            .expect("in-memory persister is infallible")
            .pj_uri();
        let payjoin::PjParam::V2(pj_param) = pj_uri.extras().pj_param() else {
            panic!("receiver URI must carry a v2 pj param");
        };
        let sender: WithReplyKey = payjoin::send::v2::SenderBuilder::from_parts(
            PARSED_ORIGINAL_PSBT.clone(),
            pj_param,
            pj_uri.address(),
            pj_uri.amount(),
        )
        .build_recommended(payjoin::bitcoin::FeeRate::BROADCAST_MIN)
        .expect("valid sender builder")
        .save(&InMemoryPersister::default())
        .expect("in-memory persister is infallible")
        .into();

        let ctx = sender.create_v2_post_request(EXAMPLE_URL.to_string()).expect("valid request");
        // An undersized body is a transient failure, so a caller may retry.
        // Retrying with the same, now consumed, context must return an error.
        sender.process_response(&[0u8; 1], &ctx.ohttp_ctx).expect("first use of the context");
        let reused = sender.process_response(&[0u8; 1], &ctx.ohttp_ctx);
        assert!(matches!(reused, Err(ClientResponseError::AlreadyUsed)));
    }
}
