//! Payjoin v1 URI functionality

use super::{PjParam, PjParseError};
use crate::uri::error::InternalPjParseError;

impl super::PjParam {
    /// Temporary and footgunny constructor that lets any URL be used as v1
    pub fn new(url: impl crate::IntoUrl) -> Result<Self, PjParseError> {
        PjParam::try_from(url.into_url().map_err(InternalPjParseError::IntoUrl)?)
    }
}
