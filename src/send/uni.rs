use std::sync::Arc;

use crate::error::PayjoinError;
use crate::{ClientResponse, PjUri, Request, Url};

#[derive(uniffi::Object)]
struct SenderBuilder(super::SenderBuilder);

impl From<super::SenderBuilder> for SenderBuilder {
    fn from(value: super::SenderBuilder) -> Self {
        Self(value)
    }
}

impl From<SenderBuilder> for super::SenderBuilder {
    fn from(value: SenderBuilder) -> Self {
        value.0
    }
}

#[uniffi::export]
impl SenderBuilder {
    /// Prepare an HTTP request and request context to process the response
    ///
    /// Call [`SenderBuilder::build_recommended()`] or other `build` methods
    /// to create a [`Sender`]
    #[uniffi::constructor]
    pub fn new(psbt: String, uri: Arc<PjUri>) -> Result<Self, PayjoinError> {
        super::SenderBuilder::new(psbt, (*uri).clone()).map(Into::into).map_err(Into::into)
    }

    /// Disable output substitution even if the receiver didn't.
    ///
    /// This forbids receiver switching output or decreasing amount.
    /// It is generally **not** recommended to set this as it may prevent the receiver from
    /// doing advanced operations such as opening LN channels and it also guarantees the
    /// receiver will **not** reward the sender with a discount.
    pub fn always_disable_output_substitution(&self, disable: bool) -> Self {
        self.0.always_disable_output_substitution(disable).into()
    }
    // Calculate the recommended fee contribution for an Original PSBT.
    //
    // BIP 78 recommends contributing `originalPSBTFeeRate * vsize(sender_input_type)`.
    // The minfeerate parameter is set if the contribution is available in change.
    //
    // This method fails if no recommendation can be made or if the PSBT is malformed.
    pub fn build_recommended(&self, min_fee_rate: u64) -> Result<Arc<Sender>, PayjoinError> {
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
    ) -> Result<Arc<Sender>, PayjoinError> {
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
    pub fn build_non_incentivizing(&self, min_fee_rate: u64) -> Result<Arc<Sender>, PayjoinError> {
        self.0.build_non_incentivizing(min_fee_rate).map(|e| Arc::new(e.into()))
    }
}

#[derive(uniffi::Object)]
struct Sender(super::Sender);

impl From<super::Sender> for Sender {
    fn from(value: super::Sender) -> Self {
        Self(value)
    }
}

impl From<Sender> for super::Sender {
    fn from(value: Sender) -> Self {
        value.0
    }
}

#[uniffi::export]
impl Sender {
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
        ohttp_proxy_url: Arc<Url>,
    ) -> Result<RequestV2PostContext, PayjoinError> {
        match self.0.extract_v2((*ohttp_proxy_url).clone()) {
            Ok((req, ctx)) => Ok(RequestV2PostContext { request: req, context: Arc::new(ctx) }),
            Err(e) => Err(e),
        }
    }

    pub fn to_json(&self) -> Result<String, PayjoinError> {
        self.0.to_json()
    }

    #[uniffi::constructor]
    pub fn from_json(json: &str) -> Result<Self, PayjoinError> {
        super::Sender::from_json(json).map(Into::into)
    }
}

#[derive(uniffi::Object)]
pub struct RequestV2PostContext {
    pub request: Request,
    pub context: Arc<super::V2PostContext>,
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
    fn from(value: super::V1Context) -> Self {
        Self(value)
    }
}

#[uniffi::export]
impl V1Context {
    /// Decodes and validates the response.
    /// Call this method with response from receiver to continue BIP78 flow. If the response is valid you will get appropriate PSBT that you should sign and broadcast.
    pub fn process_response(&self, response: Vec<u8>) -> Result<String, PayjoinError> {
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
    pub fn process_response(&self, response: &[u8]) -> Result<Arc<V2GetContext>, PayjoinError> {
        self.0.process_response(response).map(|t| Arc::new(t.into()))
    }
}

impl From<super::V2PostContext> for V2PostContext {
    fn from(value: super::V2PostContext) -> Self {
        Self(value)
    }
}

#[derive(uniffi::Record)]
pub struct RequestOhttpContext {
    pub request: crate::Request,
    pub ohttp_ctx: Arc<crate::ClientResponse>,
}

#[derive(uniffi::Object)]
pub struct V2GetContext(super::V2GetContext);

impl From<super::V2GetContext> for V2GetContext {
    fn from(value: super::V2GetContext) -> Self {
        Self(value)
    }
}

#[uniffi::export]
impl V2GetContext {
    pub fn extract_req(&self, ohttp_relay: String) -> Result<RequestOhttpContext, PayjoinError> {
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
    ) -> Result<Option<String>, PayjoinError> {
        self.0.process_response(response, ohttp_ctx.as_ref())
    }
}
