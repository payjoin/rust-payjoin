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
    pub fn from_str(uri: String) -> Result<Self, PayjoinError> {
        match payjoin::Uri::from_str(uri.as_str()) {
            Ok(e) => Ok(e.assume_checked().into()),
            Err(e) => Err(PayjoinError::PjParseError { message: e.to_string() }),
        }
    }
    pub fn address(&self) -> String {
        self.clone().0.address.to_string()
    }
    /// Gets the amount in satoshis.
    pub fn amount_sats(&self) -> Option<u64> {
        self.0.amount.map(|x| x.to_sat())
    }
    #[cfg(not(feature = "uniffi"))]
    pub fn check_pj_supported(&self) -> Result<PjUri, PayjoinError> {
        match self.0.clone().check_pj_supported() {
            Ok(e) => Ok(e.into()),
            Err(_) => {
                Err(PayjoinError::PjNotSupported {
                    message: "Uri doesn't support payjoin".to_string(),
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
                    message: "Uri doesn't support payjoin".to_string(),
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
    pub fn from_str(input: String) -> Result<Url, PayjoinError> {
        match payjoin::Url::from_str(input.as_str()) {
            Ok(e) => Ok(Self(e)),
            Err(e) => Err(PayjoinError::UnexpectedError { message: e.to_string() }),
        }
    }
    pub fn query(&self) -> Option<String> {
        self.0.query().map(|x| x.to_string())
    }
    pub fn as_string(&self) -> String {
        self.0.to_string()
    }
}

///Build a valid PjUri.
// Payjoin receiver can use this builder to create a payjoin uri to send to the sender.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct PjUriBuilder(pub payjoin::PjUriBuilder);

impl From<payjoin::PjUriBuilder> for PjUriBuilder {
    fn from(value: payjoin::PjUriBuilder) -> Self {
        Self(value)
    }
}
#[cfg(feature = "uniffi")]
#[cfg_attr(feature = "uniffi", uniffi::export)]
impl PjUriBuilder {
    /// Accepts the amount you want to receive in sats.
    pub fn amount_sats(&self, amount: u64) -> Arc<Self> {
        let amount = payjoin::bitcoin::Amount::from_sat(amount);
        Arc::new(self.0.clone().amount(amount).into())
    }
    /// Set the message.
    pub fn message(&self, message: String) -> Arc<Self> {
        Arc::new(self.0.clone().message(message).into())
    }
    ///Set the label.
    pub fn label(&self, label: String) -> Arc<Self> {
        Arc::new(self.0.clone().label(label).into())
    }
    ///Set whether payjoin output substitution is allowed.
    pub fn pjos(&self, pjos: bool) -> Arc<Self> {
        Arc::new(self.0.clone().pjos(pjos).into())
    }
    ///Constructs a Uri with PayjoinParams from the parameters set in the builder.
    pub fn build(&self) -> Arc<PjUri> {
        Arc::new(self.0.clone().build().into())
    }
}

#[cfg(not(feature = "uniffi"))]
impl PjUriBuilder {
    /// Accepts the amount you want to receive in sats.
    pub fn amount_sats(&self, sats: u64) -> Self {
        let amount = payjoin::bitcoin::Amount::from_sat(sats);
        self.0.clone().amount(amount).into()
    }
    /// Set the message.
    pub fn message(&self, message: String) -> Self {
        self.0.clone().message(message).into()
    }
    ///Set the label.
    pub fn label(&self, label: String) -> Self {
        self.0.clone().label(label).into()
    }
    ///Set whether payjoin output substitution is allowed.
    pub fn pjos(&self, pjos: bool) -> Self {
        self.0.clone().pjos(pjos).into()
    }
    ///Constructs a Uri with PayjoinParams from the parameters set in the builder.
    pub fn build(&self) -> PjUri {
        self.0.clone().build().into()
    }
}
