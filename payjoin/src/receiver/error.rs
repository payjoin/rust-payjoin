#[derive(Debug)]
pub struct RequestError(InternalRequestError);

#[derive(Debug)]
pub(crate) enum InternalRequestError {
    Decode(bitcoin::consensus::encode::Error),
    MissingHeader(&'static str),
    InvalidContentType(String),
    InvalidContentLength(std::num::ParseIntError),
    ContentLengthTooLarge(u64),
    SenderParams(super::optional_parameters::Error),
    /// The raw PSBT fails bip78-specific validation.
    Psbt(crate::psbt::InconsistentPsbt),
    /// The Original PSBT has no output for the receiver.
    MissingPayment,
    /// minimum is amount but additionalfeecontribution is (amount, index)
    InsufficientFee(bitcoin::Amount, Option<(bitcoin::Amount, usize)>),
}

impl From<InternalRequestError> for RequestError {
    fn from(value: InternalRequestError) -> Self { RequestError(value) }
}
