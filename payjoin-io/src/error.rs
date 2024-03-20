#[derive(Debug)]
pub struct Error(pub(crate) InternalError);

#[derive(Debug)]
pub(crate) enum InternalError {
    Ohttp(ohttp::Error),
    Bhttp(bhttp::Error),
    ParseUrl(url::ParseError),
    Ureq(ureq::Error),
    Io(std::io::Error),
    JoinError(tokio::task::JoinError),
}

macro_rules! impl_from_error {
    ($from:ty, $to:ident) => {
        impl From<$from> for Error {
            fn from(value: $from) -> Self { Self(InternalError::$to(value)) }
        }
    };
}

impl_from_error!(ohttp::Error, Ohttp);
impl_from_error!(bhttp::Error, Bhttp);
impl_from_error!(url::ParseError, ParseUrl);
impl_from_error!(ureq::Error, Ureq);
impl_from_error!(std::io::Error, Io);
impl_from_error!(tokio::task::JoinError, JoinError);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use InternalError::*;

        match &self.0 {
            Ohttp(e) => e.fmt(f),
            Bhttp(e) => e.fmt(f),
            ParseUrl(e) => e.fmt(f),
            Ureq(e) => e.fmt(f),
            Io(e) => e.fmt(f),
            JoinError(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use InternalError::*;

        match &self.0 {
            Ohttp(e) => Some(e),
            Bhttp(e) => Some(e),
            ParseUrl(e) => Some(e),
            Ureq(e) => Some(e),
            Io(e) => Some(e),
            JoinError(e) => Some(e),
        }
    }
}

impl From<InternalError> for Error {
    fn from(value: InternalError) -> Self { Self(value) }
}
