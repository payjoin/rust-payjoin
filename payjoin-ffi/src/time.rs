#[derive(Clone, uniffi::Object)]
pub struct Time(pub(crate) payjoin::Time);

#[uniffi::export]
impl Time {
    /// Get the current time.
    #[uniffi::constructor]
    pub fn now() -> Self { Self(payjoin::Time::now()) }

    /// Create a time value from a u32 UNIX timestamp representation.
    #[uniffi::constructor]
    pub fn from_unix_seconds(seconds: u32) -> Result<Self, ConversionError> {
        Ok(Time(payjoin::Time::from_unix_seconds(seconds)?))
    }
}

#[derive(Debug, thiserror::Error, uniffi::Object)]
#[error(transparent)]
pub struct ConversionError(#[from] payjoin::time::ConversionError);
