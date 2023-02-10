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
    /// The prevtxout is missing
    PrevTxOut(crate::psbt::PrevTxOutError),
    /// The Original PSBT has no output for the receiver.
    MissingPayment,
    /// minimum is amount but additionalfeecontribution is (amount, index)
    InsufficientFee(bitcoin::Amount, Option<(bitcoin::Amount, usize)>),
    /// The original PSBT transaction fails the broadcast check
    OriginalPsbtNotBroadcastable,
    /// The sender is trying to spend the receiver input
    InputOwned(bitcoin::Script),
    /// The original psbt has mixed input address types that could harm privacy
    MixedInputScripts(crate::input_type::InputType, crate::input_type::InputType),
    /// Unrecognized input type
    InputType(crate::input_type::InputTypeError),
    /// Original psbt input has been seen before. This is a bigger problem for "interactive" receivers
    InputSeen(bitcoin::OutPoint),
}

impl From<InternalRequestError> for RequestError {
    fn from(value: InternalRequestError) -> Self { RequestError(value) }
}
