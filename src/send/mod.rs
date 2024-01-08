pub mod v2;

use std::io::Cursor;
use std::str::FromStr;
use std::sync::Arc;

pub use payjoin::send::RequestBuilder as PdkRequestBuilder;

use crate::error::PayjoinError;
use crate::send::v2::ContextV2;
use crate::types::Request;
use crate::uri::Uri;

///Builder for sender-side payjoin parameters
///
///These parameters define how client wants to handle Payjoin.
#[derive(Clone)]
pub struct RequestBuilder(PdkRequestBuilder<'static>);

impl From<PdkRequestBuilder<'static>> for RequestBuilder {
    fn from(value: PdkRequestBuilder<'static>) -> Self {
        Self(value)
    }
}

impl RequestBuilder {
    /// Prepare an HTTP request and request context to process the response
    ///
    /// An HTTP client will own the Request data while Context sticks around so
    /// a `(Request, Context)` tuple is returned from `RequestBuilder::build()`
    /// to keep them separated.
    pub fn from_psbt_and_uri(psbt: String, uri: Arc<Uri>) -> Result<Self, PayjoinError> {
        let psbt = payjoin::bitcoin::psbt::PartiallySignedTransaction::from_str(psbt.as_str())?;
        match PdkRequestBuilder::from_psbt_and_uri(psbt, (*uri).clone().into()) {
            Ok(e) => Ok(e.into()),
            Err(e) => Err(e.into()),
        }
    }

    /// Disable output substitution even if the receiver didn't.
    ///
    /// This forbids receiver switching output or decreasing amount.
    /// It is generally **not** recommended to set this as it may prevent the receiver from
    /// doing advanced operations such as opening LN channels and it also guarantees the
    /// receiver will **not** reward the sender with a discount.
    pub fn always_disable_output_substitution(&self, disable: bool) -> Arc<Self> {
        Arc::new(self.0.clone().always_disable_output_substitution(disable).into())
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
    ) -> Result<Arc<RequestContext>, PayjoinError> {
        match self
            .0
            .clone()
            .build_recommended(payjoin::bitcoin::FeeRate::from_sat_per_kwu(min_fee_rate))
        {
            Ok(e) => Ok(Arc::new(e.into())),
            Err(e) => Err(e.into()),
        }
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
    ) -> Result<Arc<RequestContext>, PayjoinError> {
        match self.0.clone().build_with_additional_fee(
            payjoin::bitcoin::Amount::from_sat(max_fee_contribution),
            change_index.map(|x| x as usize),
            payjoin::bitcoin::FeeRate::from_sat_per_kwu(min_fee_rate),
            clamp_fee_contribution,
        ) {
            Ok(e) => Ok(Arc::new(e.into())),
            Err(e) => Err(e.into()),
        }
    }
    /// Perform Payjoin without incentivizing the payee to cooperate.
    ///
    /// While it's generally better to offer some contribution some users may wish not to.
    /// This function disables contribution.
    pub fn build_non_incentivizing(&self) -> Result<Arc<RequestContext>, PayjoinError> {
        match self.0.clone().build_non_incentivizing() {
            Ok(e) => Ok(Arc::new(e.into())),
            Err(e) => Err(e.into()),
        }
    }
}
#[derive(Clone)]
pub struct RequestContext(payjoin::send::RequestContext);

impl From<payjoin::send::RequestContext> for RequestContext {
    fn from(value: payjoin::send::RequestContext) -> Self {
        RequestContext(value)
    }
}

#[derive(Clone)]
pub struct RequestContextV1 {
    pub request: Request,
    pub context_v1: Arc<ContextV1>,
}

#[derive(Clone)]
pub struct RequestContextV2 {
    pub request: Request,
    pub context_v2: Arc<ContextV2>,
}

impl RequestContext {
    /// Extract serialized V1 Request and Context from a Payjoin Proposal
    pub fn extract_v1(&self) -> Result<RequestContextV1, PayjoinError> {
        match self.0.clone().extract_v1() {
            Ok(e) => Ok(RequestContextV1 { request: e.0.into(), context_v1: Arc::new(e.1.into()) }),
            Err(e) => Err(e.into()),
        }
    }
    /// Extract serialized Request and Context from a Payjoin Proposal.
    ///
    /// In order to support polling, this may need to be called many times to be encrypted with
    /// new unique nonces to make independent OHTTP requests.
    ///
    /// The `ohttp_proxy` merely passes the encrypted payload to the ohttp gateway of the receiver
    pub fn extract_v2(&self, ohttp_proxy_url: String) -> Result<RequestContextV2, PayjoinError> {
        match self.0.clone().extract_v2(ohttp_proxy_url.as_str()) {
            Ok(e) => Ok(RequestContextV2 { request: e.0.into(), context_v2: Arc::new(e.1.into()) }),
            Err(e) => Err(e.into()),
        }
    }
}
///Data required for validation of response.
/// This type is used to process the response. Get it from RequestBuilder's build methods. Then you only need to call .process_response() on it to continue BIP78 flow.
pub struct ContextV1(payjoin::send::ContextV1);
impl From<payjoin::send::ContextV1> for ContextV1 {
    fn from(value: payjoin::send::ContextV1) -> Self {
        Self(value)
    }
}

impl ContextV1 {
    ///Decodes and validates the response.
    /// Call this method with response from receiver to continue BIP78 flow. If the response is valid you will get appropriate PSBT that you should sign and broadcast.
    pub fn process_response(&self, response: Vec<u8>) -> Result<String, PayjoinError> {
        let mut decoder = Cursor::new(response);
        match self.0.clone().process_response(&mut decoder) {
            Ok(e) => Ok(e.to_string()),
            Err(e) => Err(e.into()),
        }
    }
}
