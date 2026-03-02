use crate::core::{Url, UrlParseError};

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    BadScheme,
    ParseError(UrlParseError),
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

impl From<UrlParseError> for Error {
    fn from(err: UrlParseError) -> Error { Error::ParseError(err) }
}

type Result<T> = core::result::Result<T, Error>;

/// Try to convert some type into a [`Url`].
///
/// This trait is "sealed", such that only types within payjoin can
/// implement it.
///
/// This design is inspired by the `reqwest` crate's design:
/// see <https://docs.rs/reqwest/latest/reqwest/trait.IntoUrl.html>
pub trait IntoUrl: IntoUrlSealed {}

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
    fn into_url(self) -> Result<Url> { self.clone().into_url() }

    fn as_str(&self) -> &str { self.as_ref() }
}

impl IntoUrlSealed for Url {
    fn into_url(self) -> Result<Url> { Ok(self) }

    fn as_str(&self) -> &str { self.as_ref() }
}

impl IntoUrlSealed for &str {
    fn into_url(self) -> Result<Url> { Url::parse(self)?.into_url() }

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
    use super::*;

    #[test]
    fn http_uri_scheme_is_allowed() {
        let url = "http://localhost".into_url().unwrap();
        assert_eq!(url.scheme(), "http");
    }

    #[test]
    fn https_uri_scheme_is_allowed() {
        let url = "https://localhost".into_url().unwrap();
        assert_eq!(url.scheme(), "https");
    }

    #[test]
    fn into_url_file_scheme() {
        let err = "file:///etc/hosts".into_url().unwrap_err();
        assert_eq!(err.to_string(), "empty host");
    }

    #[test]
    fn into_url_blob_scheme() {
        let err = "blob:https://example.com".into_url().unwrap_err();
        assert_eq!(err.to_string(), "invalid format");
    }

    #[test]
    fn into_url_rejects_userinfo() {
        let err = "http://user@example.com/".into_url().unwrap_err();
        assert_eq!(err.to_string(), "invalid host");
    }

    #[test]
    fn into_url_conversions() {
        let input = "http://localhost/";
        let url = Url::parse(input).unwrap();

        let url_ref = &url;
        assert_eq!(url_ref.as_str(), url.as_ref());
        assert_eq!(IntoUrlSealed::as_str(url_ref), url.as_ref());
        assert_eq!(IntoUrlSealed::as_str(&url_ref), url.as_ref());

        let url_str: &str = input;
        assert_eq!(url_str, url.as_ref());
        assert_eq!(IntoUrlSealed::as_str(&url_str), url.as_ref());

        let url_string: String = input.to_string();
        assert_eq!(url_string, url.as_ref());
        assert_eq!(IntoUrlSealed::as_str(&url_string), url.as_ref());

        let url_string_ref: &String = &input.to_string();
        assert_eq!(url_string_ref, url.as_ref());
        assert_eq!(IntoUrlSealed::as_str(&url_string_ref), url.as_ref());
    }
}
