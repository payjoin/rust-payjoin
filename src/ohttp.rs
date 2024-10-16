use crate::error::PayjoinError;

impl From<payjoin::OhttpKeys> for OhttpKeys {
    fn from(value: payjoin::OhttpKeys) -> Self {
        Self(value)
    }
}
impl From<OhttpKeys> for payjoin::OhttpKeys {
    fn from(value: OhttpKeys) -> Self {
        value.0
    }
}
#[derive(Debug, Clone)]
pub struct OhttpKeys(pub payjoin::OhttpKeys);
impl OhttpKeys {
    /// Decode an OHTTP KeyConfig
    pub fn decode(bytes: Vec<u8>) -> Result<Self, PayjoinError> {
        payjoin::OhttpKeys::decode(bytes.as_slice()).map(|e| e.into()).map_err(|e| e.into())
    }
}
