use std::str::FromStr;
use std::sync::{Arc, RwLock};

use bitcoin_ffi::Psbt;
pub use error::{BuildSenderError, CreateRequestError, EncapsulationError, ResponseError};
use payjoin::persist::SessionPersister;

pub use crate::error::{ImplementationError, SerdeJsonError};
use crate::ohttp::ClientResponse;
use crate::request::Request;
use crate::send::error::{SenderPersistedError, SenderReplayError};
use crate::uri::PjUri;

pub mod error;
#[cfg(feature = "uniffi")]
pub mod uni;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionEvent(payjoin::send::v2::SessionEvent);

impl From<SessionEvent> for payjoin::send::v2::SessionEvent {
    fn from(value: SessionEvent) -> Self { value.0 }
}

impl From<payjoin::send::v2::SessionEvent> for SessionEvent {
    fn from(value: payjoin::send::v2::SessionEvent) -> Self { SessionEvent(value) }
}

#[derive(Debug, Clone)]
pub struct SenderTypeState(payjoin::send::v2::SenderTypeState);

impl From<payjoin::send::v2::SenderTypeState> for SenderTypeState {
    fn from(value: payjoin::send::v2::SenderTypeState) -> Self { Self(value) }
}

pub fn replay_event_log<P>(persister: &P) -> Result<(SenderTypeState, SessionHistory), SenderReplayError>
where
    P: SessionPersister + Clone,
    P::SessionEvent: Into<payjoin::send::v2::SessionEvent> + Clone,
{
    let (state, history) =
        payjoin::send::v2::replay_event_log(persister).map_err(SenderReplayError::from)?;
    Ok((state.into(), history.into()))
}

#[derive(Default, Clone)]
pub struct SessionHistory(pub payjoin::send::v2::SessionHistory);

impl From<payjoin::send::v2::SessionHistory> for SessionHistory {
    fn from(value: payjoin::send::v2::SessionHistory) -> Self { Self(value) }
}

pub struct InitInputsTransition(
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

impl InitInputsTransition {
    pub fn save<P>(&self, persister: &P) -> Result<WithReplyKey, SenderPersistedError>
    where
        P: SessionPersister<SessionEvent = payjoin::send::v2::SessionEvent>,
    {
        let mut inner =
            self.0.write().map_err(|_| SenderPersistedError::Storage(Arc::new(ImplementationError::from("Lock poisoned".to_string()))))?;

        let value = inner
            .take()
            .ok_or_else(|| SenderPersistedError::Storage(Arc::new(ImplementationError::from("Already saved or moved".to_string()))))?;

        let res = value.save(persister).map_err(|e| SenderPersistedError::from(e))?;
        Ok(res.into())
    }
}

///Builder for sender-side payjoin parameters
///
///These parameters define how client wants to handle Payjoin.
#[derive(Clone)]
pub struct SenderBuilder(payjoin::send::v2::SenderBuilder<'static>);

impl From<payjoin::send::v2::SenderBuilder<'static>> for SenderBuilder {
    fn from(value: payjoin::send::v2::SenderBuilder<'static>) -> Self { Self(value) }
}

impl SenderBuilder {
    /// Prepare an HTTP request and request context to process the response
    ///
    /// Call [`SenderBuilder::build_recommended()`] or other `build` methods
    /// to create a [`WithReplyKey`]
    pub fn new(psbt: String, uri: PjUri) -> Result<Self, BuildSenderError> {
        let psbt = payjoin::bitcoin::psbt::Psbt::from_str(psbt.as_str())?;
        Ok(payjoin::send::v2::SenderBuilder::new(psbt, uri.into()).into())
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
    pub fn build_recommended(&self, min_fee_rate: u64) -> InitInputsTransition {
        InitInputsTransition(Arc::new(RwLock::new(Some(
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
    ) -> InitInputsTransition {
        InitInputsTransition(Arc::new(RwLock::new(Some(self.0.clone().build_with_additional_fee(
            payjoin::bitcoin::Amount::from_sat(max_fee_contribution),
            change_index.map(|x| x as usize),
            payjoin::bitcoin::FeeRate::from_sat_per_kwu(min_fee_rate),
            clamp_fee_contribution,
        )))))
    }
    /// Perform Payjoin without incentivizing the payee to cooperate.
    ///
    /// While it's generally better to offer some contribution some users may wish not to.
    /// This function disables contribution.
    pub fn build_non_incentivizing(&self, min_fee_rate: u64) -> InitInputsTransition {
        InitInputsTransition(Arc::new(RwLock::new(Some(
            self.0
                .clone()
                .build_non_incentivizing(payjoin::bitcoin::FeeRate::from_sat_per_kwu(min_fee_rate)),
        ))))
    }
}

#[derive(Clone)]
pub struct WithReplyKey(payjoin::send::v2::Sender<payjoin::send::v2::WithReplyKey>);

impl From<payjoin::send::v2::Sender<payjoin::send::v2::WithReplyKey>> for WithReplyKey {
    fn from(value: payjoin::send::v2::Sender<payjoin::send::v2::WithReplyKey>) -> Self {
        Self(value)
    }
}

impl From<WithReplyKey> for payjoin::send::v2::Sender<payjoin::send::v2::WithReplyKey> {
    fn from(value: WithReplyKey) -> Self { value.0 }
}

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

impl WithReplyKeyTransition {
    pub fn save<P>(&self, persister: &P) -> Result<V2GetContext, SenderPersistedError>
    where
        P: SessionPersister<SessionEvent = payjoin::send::v2::SessionEvent>,
    {
        let mut inner =
            self.0.write().map_err(|_| SenderPersistedError::Storage(Arc::new(ImplementationError::from("Lock poisoned".to_string()))))?;

        let value = inner
            .take()
            .ok_or_else(|| SenderPersistedError::Storage(Arc::new(ImplementationError::from("Already saved or moved".to_string()))))?;

        let res = value.save(persister).map_err(|e| SenderPersistedError::from(e))?;
        Ok(res.into())
    }
}

impl WithReplyKey {
    pub fn extract_v1(&self) -> (Request, V1Context) {
        let (req, ctx) = self.0.clone().extract_v1();
        (req.into(), ctx.into())
    }

    /// Extract serialized Request and Context from a Payjoin Proposal.
    pub fn extract_v2(
        &self,
        ohttp_relay: String,
    ) -> Result<(Request, V2PostContext), CreateRequestError> {
        match self.0.extract_v2(ohttp_relay) {
            Ok((req, ctx)) => Ok((req.into(), ctx.into())),
            Err(e) => Err(e.into()),
        }
    }

    /// Decodes and validates the response.
    /// Call this method with response from receiver to continue BIP-??? flow. A successful response can either be None if the relay has not response yet or Some(Psbt).
    /// If the response is some valid PSBT you should sign and broadcast.
    pub fn process_response(
        &self,
        response: &[u8],
        post_ctx: V2PostContext,
    ) -> WithReplyKeyTransition {
        WithReplyKeyTransition(Arc::new(RwLock::new(Some(
            self.clone().0.process_response(response, post_ctx.into()),
        ))))
    }

    pub fn to_json(&self) -> Result<String, SerdeJsonError> {
        serde_json::to_string(&self.0).map_err(Into::into)
    }

    pub fn from_json(json: &str) -> Result<Self, SerdeJsonError> {
        serde_json::from_str::<payjoin::send::v2::Sender<payjoin::send::v2::WithReplyKey>>(json)
            .map_err(Into::into)
            .map(Into::into)
    }
}

/// Data required for validation of response.
/// This type is used to process the response. Get it from SenderBuilder's build methods. Then you only need to call .process_response() on it to continue BIP78 flow.
#[derive(Clone)]
pub struct V1Context(Arc<payjoin::send::v1::V1Context>);
impl From<payjoin::send::v1::V1Context> for V1Context {
    fn from(value: payjoin::send::v1::V1Context) -> Self { Self(Arc::new(value)) }
}

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

pub struct V2PostContext(payjoin::send::v2::V2PostContext);

impl From<V2PostContext> for payjoin::send::v2::V2PostContext {
    fn from(value: V2PostContext) -> Self { value.0 }
}

impl From<payjoin::send::v2::V2PostContext> for V2PostContext {
    fn from(value: payjoin::send::v2::V2PostContext) -> Self { Self(value) }
}

pub struct V2GetContext(payjoin::send::v2::Sender<payjoin::send::v2::V2GetContext>);

impl From<payjoin::send::v2::Sender<payjoin::send::v2::V2GetContext>> for V2GetContext {
    fn from(value: payjoin::send::v2::Sender<payjoin::send::v2::V2GetContext>) -> Self {
        Self(value)
    }
}

pub struct V2GetContextTransitionOutcome(
    payjoin::persist::OptionalTransitionOutcome<
        payjoin::bitcoin::Psbt,
        payjoin::send::v2::Sender<payjoin::send::v2::V2GetContext>,
    >,
);

impl V2GetContextTransitionOutcome {
    pub fn is_none(&self) -> bool { self.0.is_none() }

    pub fn is_success(&self) -> bool { self.0.is_success() }

    pub fn success(&self) -> Option<Psbt> {
        self.0.success().map(|r| r.clone().into())
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

impl V2GetContextTransition {
    pub fn save<P>(&self, persister: &P) -> Result<V2GetContextTransitionOutcome, SenderPersistedError>
    where
        P: SessionPersister<SessionEvent = payjoin::send::v2::SessionEvent>,
    {
        let mut inner =
            self.0.write().map_err(|_| SenderPersistedError::Storage(Arc::new(ImplementationError::from("Lock poisoned".to_string()))))?;

        let value = inner
            .take()
            .ok_or_else(|| SenderPersistedError::Storage(Arc::new(ImplementationError::from("Already saved or moved".to_string()))))?;

        let res = value.save(persister).map_err(|e| SenderPersistedError::from(e))?;
        Ok(res.into())
    }
}

impl V2GetContext {
    pub fn extract_req(
        &self,
        ohttp_relay: String,
    ) -> Result<(Request, ClientResponse), CreateRequestError> {
        self.0
            .extract_req(ohttp_relay)
            .map(|(req, ctx)| (req.into(), ctx.into()))
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
