//! Payjoin v1 URI functionality

use url::Url;

use super::PjParseError;
use crate::uri::error::InternalPjParseError;

/// Payjoin v1 parameter containing the endpoint URL
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PjParam(Url);

impl PjParam {
    /// Parse a new v1 PjParam from a URL
    pub(super) fn parse(url: Url) -> Result<Self, PjParseError> {
        if url.scheme() == "https"
            || url.scheme() == "http" && url.domain().unwrap_or_default().ends_with(".onion")
        {
            Ok(Self(url))
        } else {
            Err(InternalPjParseError::UnsecureEndpoint.into())
        }
    }

    /// Get the endpoint URL
    pub(crate) fn endpoint(&self) -> Url { self.0.clone() }
}

impl std::fmt::Display for PjParam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Use the same display logic as the encapsulated child Url
        self.0.fmt(f)
    }
}
