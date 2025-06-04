use std::sync::Arc;

use crate::error::ForeignError;
pub use crate::send::{
    BuildSenderError, CreateRequestError, EncapsulationError, ResponseError, SerdeJsonError,
};
use crate::{ClientResponse, ImplementationError, PjUri, Request};

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
    pub fn build_recommended(&self, min_fee_rate: u64) -> Result<Arc<NewSender>, BuildSenderError> {
        self.0.build_recommended(min_fee_rate).map(|e| Arc::new(e.into()))
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
    ) -> Result<Arc<NewSender>, BuildSenderError> {
        self.0
            .build_with_additional_fee(
                max_fee_contribution,
                change_index,
                min_fee_rate,
                clamp_fee_contribution,
            )
            .map(|e| Arc::new(e.into()))
    }
    /// Perform Payjoin without incentivizing the payee to cooperate.
    ///
    /// While it's generally better to offer some contribution some users may wish not to.
    /// This function disables contribution.
    pub fn build_non_incentivizing(
        &self,
        min_fee_rate: u64,
    ) -> Result<Arc<NewSender>, BuildSenderError> {
        self.0.build_non_incentivizing(min_fee_rate).map(|e| Arc::new(e.into()))
    }
}

#[derive(uniffi::Object)]
pub struct NewSender(super::NewSender);

impl From<super::NewSender> for NewSender {
    fn from(value: super::NewSender) -> Self { Self(value) }
}

#[uniffi::export]
impl NewSender {
    pub fn persist(
        &self,
        persister: Arc<dyn SenderPersister>,
    ) -> Result<SenderToken, ImplementationError> {
        let mut adapter = CallbackPersisterAdapter::new(persister);
        self.0.persist(&mut adapter)
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

#[uniffi::export]
impl WithReplyKey {
    #[uniffi::constructor]
    pub fn load(
        token: Arc<SenderToken>,
        persister: Arc<dyn SenderPersister>,
    ) -> Result<Self, ImplementationError> {
        Ok(super::WithReplyKey::from(
            (*persister.load(token).map_err(|e| ImplementationError::from(e.to_string()))?).clone(),
        )
        .into())
    }

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

    pub fn to_json(&self) -> Result<String, SerdeJsonError> { self.0.to_json() }

    #[uniffi::constructor]
    pub fn from_json(json: &str) -> Result<Self, SerdeJsonError> {
        super::WithReplyKey::from_json(json).map(Into::into)
    }

    pub fn key(&self) -> SenderToken { self.0.key().into() }
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
    pub fn process_response(&self, response: Vec<u8>) -> Result<String, ResponseError> {
        self.0.process_response(response)
    }
}

#[derive(uniffi::Object)]
pub struct V2PostContext(super::V2PostContext);

#[uniffi::export]
impl V2PostContext {
    /// Decodes and validates the response.
    /// Call this method with response from receiver to continue BIP-??? flow. A successful response can either be None if the relay has not response yet or Some(Psbt).
    /// If the response is some valid PSBT you should sign and broadcast.
    pub fn process_response(
        &self,
        response: &[u8],
    ) -> Result<Arc<V2GetContext>, EncapsulationError> {
        self.0.process_response(response).map(|t| Arc::new(t.into()))
    }
}

impl From<super::V2PostContext> for V2PostContext {
    fn from(value: super::V2PostContext) -> Self { Self(value) }
}

#[derive(uniffi::Record)]
pub struct RequestOhttpContext {
    pub request: crate::Request,
    pub ohttp_ctx: Arc<crate::ClientResponse>,
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
    ) -> Result<Option<String>, ResponseError> {
        self.0.process_response(response, ohttp_ctx.as_ref())
    }
}

#[uniffi::export(with_foreign)]
pub trait SenderPersister: Send + Sync {
    fn save(&self, sender: Arc<WithReplyKey>) -> Result<Arc<SenderToken>, ForeignError>;
    fn load(&self, token: Arc<SenderToken>) -> Result<Arc<WithReplyKey>, ForeignError>;
}

// The adapter to use the save and load callbacks
struct CallbackPersisterAdapter {
    callback_persister: Arc<dyn SenderPersister>,
}

impl CallbackPersisterAdapter {
    pub fn new(callback_persister: Arc<dyn SenderPersister>) -> Self { Self { callback_persister } }
}

// Implement the Persister trait for the adapter
impl payjoin::persist::Persister<payjoin::send::v2::Sender<payjoin::send::v2::WithReplyKey>>
    for CallbackPersisterAdapter
{
    type Token = SenderToken; // Define the token type
    type Error = ForeignError; // Define the error type

    fn save(
        &mut self,
        sender: payjoin::send::v2::Sender<payjoin::send::v2::WithReplyKey>,
    ) -> Result<Self::Token, Self::Error> {
        let sender = WithReplyKey(super::WithReplyKey::from(sender));
        self.callback_persister.save(sender.into()).map(|token| (*token).clone())
    }

    fn load(
        &self,
        token: Self::Token,
    ) -> Result<payjoin::send::v2::Sender<payjoin::send::v2::WithReplyKey>, Self::Error> {
        // Use the callback to load the sender
        self.callback_persister.load(token.into()).map(|sender| (*sender).clone().0 .0)
    }
}

#[derive(Clone, Debug, uniffi::Object)]
#[uniffi::export(Display)]
pub struct SenderToken(#[allow(dead_code)] payjoin::send::v2::SenderToken);

impl std::fmt::Display for SenderToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) }
}

impl From<payjoin::send::v2::Sender<payjoin::send::v2::WithReplyKey>> for SenderToken {
    fn from(value: payjoin::send::v2::Sender<payjoin::send::v2::WithReplyKey>) -> Self {
        SenderToken(value.into())
    }
}

impl From<payjoin::send::v2::SenderToken> for SenderToken {
    fn from(value: payjoin::send::v2::SenderToken) -> Self { SenderToken(value) }
}
