pub struct RequestError(InternalRequestError);

pub(crate) enum InternalRequestError {
    Decode(bitcoin::consensus::encode::Error),
    MissingHeader(&'static str),
    InvalidContentType(String),
    InvalidContentLength(std::num::ParseIntError),
    ContentLengthTooLarge(u64),
}

impl From<InternalRequestError> for RequestError {
    fn from(value: InternalRequestError) -> Self {
        RequestError(value)
    }
}
