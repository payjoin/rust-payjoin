use std::io::Cursor;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

pub use error::{BuildSenderError, CreateRequestError, EncapsulationError, ResponseError};

use crate::error::PayjoinError;
use crate::ohttp::ClientResponse;
use crate::request::Request;
use crate::uri::{PjUri, Url};

pub mod error;
#[cfg(feature = "uniffi")]
pub mod uni;

///Builder for sender-side payjoin parameters
///
///These parameters define how client wants to handle Payjoin.
#[derive(Clone)]
pub struct SenderBuilder(payjoin::send::v2::SenderBuilder<'static>);

impl From<payjoin::send::v2::SenderBuilder<'static>> for SenderBuilder {
    fn from(value: payjoin::send::v2::SenderBuilder<'static>) -> Self {
        Self(value)
    }
}

impl SenderBuilder {
    /// Prepare an HTTP request and request context to process the response
    ///
    /// Call [`SenderBuilder::build_recommended()`] or other `build` methods
    /// to create a [`Sender`]
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
    pub fn always_disable_output_substitution(&self, disable: bool) -> Self {
        self.0.clone().always_disable_output_substitution(disable).into()
    }
    // Calculate the recommended fee contribution for an Original PSBT.
    //
    // BIP 78 recommends contributing `originalPSBTFeeRate * vsize(sender_input_type)`.
    // The minfeerate parameter is set if the contribution is available in change.
    //
    // This method fails if no recommendation can be made or if the PSBT is malformed.
    pub fn build_recommended(&self, min_fee_rate: u64) -> Result<Sender, BuildSenderError> {
        self.0
            .clone()
            .build_recommended(payjoin::bitcoin::FeeRate::from_sat_per_kwu(min_fee_rate))
            .map(|e| e.into())
            .map_err(|e| e.into())
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
    ) -> Result<Sender, BuildSenderError> {
        self.0
            .clone()
            .build_with_additional_fee(
                payjoin::bitcoin::Amount::from_sat(max_fee_contribution),
                change_index.map(|x| x as usize),
                payjoin::bitcoin::FeeRate::from_sat_per_kwu(min_fee_rate),
                clamp_fee_contribution,
            )
            .map(|e| e.into())
            .map_err(|e| e.into())
    }
    /// Perform Payjoin without incentivizing the payee to cooperate.
    ///
    /// While it's generally better to offer some contribution some users may wish not to.
    /// This function disables contribution.
    pub fn build_non_incentivizing(&self, min_fee_rate: u64) -> Result<Sender, BuildSenderError> {
        match self
            .0
            .clone()
            .build_non_incentivizing(payjoin::bitcoin::FeeRate::from_sat_per_kwu(min_fee_rate))
        {
            Ok(e) => Ok(e.into()),
            Err(e) => Err(e.into()),
        }
    }
}
#[derive(Clone)]
pub struct Sender(payjoin::send::v2::Sender);

impl From<payjoin::send::v2::Sender> for Sender {
    fn from(value: payjoin::send::v2::Sender) -> Self {
        Self(value)
    }
}

impl Sender {
    pub fn extract_v1(&self) -> (Request, V1Context) {
        let (req, ctx) = self.0.clone().extract_v1();
        (req.into(), ctx.into())
    }

    /// Extract serialized Request and Context from a Payjoin Proposal.
    pub fn extract_v2(
        &self,
        ohttp_relay: Url,
    ) -> Result<(Request, V2PostContext), CreateRequestError> {
        match self.0.extract_v2(ohttp_relay.into()) {
            Ok((req, ctx)) => Ok((req.into(), ctx.into())),
            Err(e) => Err(e.into()),
        }
    }

    pub fn to_json(&self) -> Result<String, PayjoinError> {
        serde_json::to_string(&self.0).map_err(|e| e.into())
    }

    pub fn from_json(json: &str) -> Result<Self, PayjoinError> {
        let sender = serde_json::from_str::<payjoin::send::v2::Sender>(json)
            .map_err(<serde_json::Error as Into<PayjoinError>>::into)?;
        Ok(sender.into())
    }
}

/// Data required for validation of response.
/// This type is used to process the response. Get it from SenderBuilder's build methods. Then you only need to call .process_response() on it to continue BIP78 flow.
#[derive(Clone)]
pub struct V1Context(Arc<payjoin::send::v1::V1Context>);
impl From<payjoin::send::v1::V1Context> for V1Context {
    fn from(value: payjoin::send::v1::V1Context) -> Self {
        Self(Arc::new(value))
    }
}

impl V1Context {
    ///Decodes and validates the response.
    /// Call this method with response from receiver to continue BIP78 flow. If the response is valid you will get appropriate PSBT that you should sign and broadcast.
    pub fn process_response(&self, response: Vec<u8>) -> Result<String, ResponseError> {
        let mut decoder = Cursor::new(response);
        <payjoin::send::v1::V1Context as Clone>::clone(&self.0.clone())
            .process_response(&mut decoder)
            .map(|e| e.to_string())
            .map_err(Into::into)
    }
}

pub struct V2PostContext(Mutex<Option<payjoin::send::v2::V2PostContext>>);

impl V2PostContext {
    /// Decodes and validates the response.
    /// Call this method with response from receiver to continue BIP-??? flow. A successful response can either be None if the relay has not response yet or Some(Psbt).
    /// If the response is some valid PSBT you should sign and broadcast.
    pub fn process_response(&self, response: &[u8]) -> Result<V2GetContext, EncapsulationError> {
        <&V2PostContext as Into<payjoin::send::v2::V2PostContext>>::into(self)
            .process_response(response)
            .map(Into::into)
            .map_err(Into::into)
    }
}

impl From<&V2PostContext> for payjoin::send::v2::V2PostContext {
    fn from(value: &V2PostContext) -> Self {
        let mut data_guard = value.0.lock().unwrap();
        Option::take(&mut *data_guard).expect("ContextV2 moved out of memory")
    }
}

impl From<payjoin::send::v2::V2PostContext> for V2PostContext {
    fn from(value: payjoin::send::v2::V2PostContext) -> Self {
        Self(Mutex::new(Some(value)))
    }
}

pub struct V2GetContext(payjoin::send::v2::V2GetContext);

impl From<payjoin::send::v2::V2GetContext> for V2GetContext {
    fn from(value: payjoin::send::v2::V2GetContext) -> Self {
        Self(value)
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
    ) -> Result<Option<String>, ResponseError> {
        match self.0.process_response(response, ohttp_ctx.into()) {
            Ok(Some(psbt)) => Ok(Some(psbt.to_string())),
            Ok(None) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}
