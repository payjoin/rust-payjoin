use std::convert::TryFrom;
use std::fmt;

use serde::{Deserialize, Serialize};
use url::ParseError;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    BadScheme,
    ParseError(ParseError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;

        match self {
            BadScheme => write!(f, "URL scheme is not allowed"),
            ParseError(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<ParseError> for Error {
    fn from(err: ParseError) -> Error { Error::ParseError(err) }
}

type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "String")]
pub struct Url(pub(crate) url::Url);

impl Url {
    pub fn as_str(&self) -> &str { self.0.as_ref() }

    fn parse(s: &str) -> std::result::Result<Self, url::ParseError> { url::Url::parse(s).map(Url) }
}

impl TryFrom<String> for Url {
    type Error = url::ParseError;

    fn try_from(s: String) -> std::result::Result<Self, Self::Error> { Url::parse(&s) }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.as_str()) }
}

/// Try to convert some type into a [`Url`].
///
/// This trait is "sealed", such that only types within payjoin can
/// implement it.
///
/// This design is inspired by the `reqwest` crate's design:
/// see <https://docs.rs/reqwest/latest/reqwest/trait.IntoUrl.html>
pub trait IntoUrl: IntoUrlSealed {}

impl IntoUrl for Url {}
impl IntoUrl for &Url {}
impl IntoUrl for &str {}
impl IntoUrl for &String {}
impl IntoUrl for String {}

pub trait IntoUrlSealed {
    /// Besides parsing as a valid `Url`, the `Url` must be a valid
    /// `http::Uri`, in that it makes sense to use in a network request.
    fn into_url(self) -> Result<Url>;

    fn as_str(&self) -> &str;
}

impl IntoUrlSealed for &Url {
    fn into_url(self) -> Result<Url> { Ok(self.clone()) }

    fn as_str(&self) -> &str { self.0.as_ref() }
}

impl IntoUrlSealed for Url {
    fn into_url(self) -> Result<Url> {
        if self.0.has_host() {
            Ok(self)
        } else {
            Err(Error::BadScheme)
        }
    }

    fn as_str(&self) -> &str { self.0.as_ref() }
}

impl IntoUrlSealed for &str {
    fn into_url(self) -> Result<Url> { Ok(Url(url::Url::parse(self)?)) }

    fn as_str(&self) -> &str { self }
}

impl IntoUrlSealed for &String {
    fn into_url(self) -> Result<Url> { (&**self).into_url() }

    fn as_str(&self) -> &str { self.as_ref() }
}

impl IntoUrlSealed for String {
    fn into_url(self) -> Result<Url> { (&*self).into_url() }

    fn as_str(&self) -> &str { self.as_ref() }
}

#[cfg(test)]
mod tests {
    use crate::core::into_url::{IntoUrlSealed, Url};

    #[test]
    fn http_uri_scheme_is_allowed() {
        let url = "http://localhost".into_url().unwrap();
        assert_eq!(url.0.scheme(), "http");
    }

    #[test]
    fn https_uri_scheme_is_allowed() {
        let url = "https://localhost".into_url().unwrap();
        assert_eq!(url.0.scheme(), "https");
    }

    #[test]
    fn into_url_file_scheme() {
        let err = Url::parse("file:///etc/hosts").unwrap().into_url().unwrap_err();
        assert_eq!(err.to_string(), "URL scheme is not allowed");
    }

    #[test]
    fn into_url_blob_scheme() {
        let err = Url::parse("blob:https://example.com").unwrap().into_url().unwrap_err();
        assert_eq!(err.to_string(), "URL scheme is not allowed");
    }

    #[test]
    fn into_url_conversions() {
        let input = "http://localhost/";
        let url = Url(url::Url::parse(input).unwrap());

        let url_ref = &url;
        assert_eq!(url_ref.as_str(), url.0.as_ref());
        assert_eq!(IntoUrlSealed::as_str(url_ref), url.0.as_ref());
        assert_eq!(IntoUrlSealed::as_str(&url_ref), url.0.as_ref());

        let url_str: &str = input;
        assert_eq!(url_str, url.0.as_ref());
        assert_eq!(IntoUrlSealed::as_str(&url_str), url.0.as_ref());

        let url_string: String = input.to_string();
        assert_eq!(url_string, url.0.as_ref());
        assert_eq!(IntoUrlSealed::as_str(&url_string), url.0.as_ref());

        let url_string_ref: &String = &input.to_string();
        assert_eq!(url_string_ref, url.0.as_ref());
        assert_eq!(IntoUrlSealed::as_str(&url_string_ref), url.0.as_ref());
    }
}
