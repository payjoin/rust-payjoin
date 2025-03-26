use std::str::FromStr;
#[cfg(feature = "uniffi")]
use std::sync::Arc;

use payjoin::bitcoin::address::NetworkChecked;
use payjoin::UriExt;

use crate::error::PayjoinError;
#[derive(Clone)]
pub struct Uri(payjoin::Uri<'static, NetworkChecked>);
impl From<Uri> for payjoin::Uri<'static, NetworkChecked> {
    fn from(value: Uri) -> Self {
        value.0
    }
}

impl From<payjoin::Uri<'static, NetworkChecked>> for Uri {
    fn from(value: payjoin::Uri<'static, NetworkChecked>) -> Self {
        Uri(value)
    }
}

impl Uri {
    pub fn parse(uri: String) -> Result<Self, PayjoinError> {
        match payjoin::Uri::from_str(uri.as_str()) {
            Ok(e) => Ok(e.assume_checked().into()),
            Err(e) => Err(PayjoinError::PjParseError { msg: e.to_string() }),
        }
    }
    pub fn address(&self) -> String {
        self.clone().0.address.to_string()
    }
    /// Gets the amount in satoshis.
    pub fn amount_sats(&self) -> Option<u64> {
        self.0.amount.map(|x| x.to_sat())
    }
    pub fn label(&self) -> Option<String> {
        self.0.label.clone().and_then(|x| String::try_from(x).ok())
    }
    pub fn message(&self) -> Option<String> {
        self.0.message.clone().and_then(|x| String::try_from(x).ok())
    }
    #[cfg(not(feature = "uniffi"))]
    pub fn check_pj_supported(&self) -> Result<PjUri, PayjoinError> {
        match self.0.clone().check_pj_supported() {
            Ok(e) => Ok(e.into()),
            Err(_) => {
                Err(PayjoinError::PjNotSupported {
                    msg: "Uri doesn't support payjoin".to_string(),
                })
            }
        }
    }
    #[cfg(feature = "uniffi")]
    pub fn check_pj_supported(&self) -> Result<Arc<PjUri>, PayjoinError> {
        match self.0.clone().check_pj_supported() {
            Ok(e) => Ok(Arc::new(e.into())),
            Err(_) => {
                Err(PayjoinError::PjNotSupported {
                    msg: "Uri doesn't support payjoin".to_string(),
                })
            }
        }
    }
    pub fn as_string(&self) -> String {
        self.0.clone().to_string()
    }
}

impl From<payjoin::PjUri<'static>> for PjUri {
    fn from(value: payjoin::PjUri<'static>) -> Self {
        Self(value)
    }
}

impl<'a> From<PjUri> for payjoin::PjUri<'a> {
    fn from(value: PjUri) -> Self {
        value.0
    }
}

#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct PjUri(pub payjoin::PjUri<'static>);

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl PjUri {
    pub fn address(&self) -> String {
        self.0.clone().address.to_string()
    }
    /// Number of sats requested as payment
    pub fn amount_sats(&self) -> Option<u64> {
        self.0.clone().amount.map(|e| e.to_sat())
    }

    pub fn pj_endpoint(&self) -> String {
        self.0.extras.endpoint().to_string()
    }

    pub fn as_string(&self) -> String {
        self.0.clone().to_string()
    }
}

impl From<payjoin::Url> for Url {
    fn from(value: payjoin::Url) -> Self {
        Self(value)
    }
}

impl From<Url> for payjoin::Url {
    fn from(value: Url) -> Self {
        value.0
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct Url(payjoin::Url);

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Url {
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn parse(input: String) -> Result<Url, PayjoinError> {
        match payjoin::Url::parse(input.as_str()) {
            Ok(e) => Ok(Self(e)),
            Err(e) => Err(PayjoinError::UnexpectedError { msg: e.to_string() }),
        }
    }
    pub fn query(&self) -> Option<String> {
        self.0.query().map(|x| x.to_string())
    }
    pub fn as_string(&self) -> String {
        self.0.to_string()
    }
}
