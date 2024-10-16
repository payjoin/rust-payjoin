use std::str::FromStr;
#[cfg(feature = "uniffi")]
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use payjoin::bitcoin::address::NetworkChecked;
use payjoin::UriExt;

use crate::error::PayjoinError;
use crate::types::OhttpKeys;
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
    ///Gets the amount in satoshis.
    pub fn amount(&self) -> Option<f64> {
        self.0.amount.map(|x| x.to_btc())
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
pub struct PjUri(pub payjoin::PjUri<'static>);

impl PjUri {
    pub fn address(&self) -> String {
        self.0.clone().address.to_string()
    }
    /// Number of btc  requested as payment
    pub fn amount(&self) -> Option<f64> {
        self.0.clone().amount.map(|e| e.to_btc())
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
pub struct Url(payjoin::Url);

impl Url {
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
pub struct PjUriBuilder(pub payjoin::PjUriBuilder);

impl From<payjoin::PjUriBuilder> for PjUriBuilder {
    fn from(value: payjoin::PjUriBuilder) -> Self {
        Self(value)
    }
}
#[cfg(feature = "uniffi")]
impl PjUriBuilder {
    ///Create a new PjUriBuilder with required parameters.
    /// Parameters
    /// address: Represents a bitcoin address.
    /// ohttp_keys: Optional OHTTP keys for v2.
    /// expiry: Optional non-default duration_since epoch expiry for the payjoin session.
    pub fn new(
        address: String,
        pj: Arc<Url>,
        ohttp_keys: Option<Arc<OhttpKeys>>,
        expiry: Option<u64>,
    ) -> Result<Self, PayjoinError> {
        let address = payjoin::bitcoin::Address::from_str(&address)?.assume_checked();
        Ok(payjoin::PjUriBuilder::new(
            address,
            (*pj).clone().into(),
            ohttp_keys.map(|e| e.0.clone()),
            expiry.map(|e| UNIX_EPOCH + Duration::from_secs(e)),
        )
        .into())
    }
    ///Accepts the amount you want to receive in sats and sets it in btc .
    pub fn amount(&self, amount: u64) -> Arc<Self> {
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
    ///Create a new PjUriBuilder with required parameters.
    /// Parameters
    /// address: Represents a bitcoin address.
    /// ohttp_keys: Optional OHTTP keys for v2.
    /// expiry: Optional non-default duration_since epoch expiry for the payjoin session.
    pub fn new(
        address: String,
        pj: Url,
        ohttp_keys: Option<OhttpKeys>,
        expiry: Option<u64>,
    ) -> Result<Self, PayjoinError> {
        let address = payjoin::bitcoin::Address::from_str(&address)?.assume_checked();
        Ok(payjoin::PjUriBuilder::new(
            address,
            pj.into(),
            ohttp_keys.map(|e| e.0),
            expiry.map(|e| UNIX_EPOCH + Duration::from_secs(e)),
        )
        .into())
    }
    ///Accepts the amount you want to receive in sats and sets it in btc .
    pub fn amount(&self, amount: u64) -> Self {
        let amount = payjoin::bitcoin::Amount::from_sat(amount);
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

#[cfg(test)]
#[cfg(not(feature = "uniffi"))]
mod tests {
    use bdk::bitcoin;

    use crate::uri::{PjUriBuilder, Url};
    #[test]
    fn test_ffi_builder() {
        let https = "https://example.com/";
        let onion = "http://vjdpwgybvubne5hda6v4c5iaeeevhge6jvo3w2cl6eocbwwvwxp7b7qd.onion/";
        let base58 = "12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX";
        let bech32_upper = "TB1Q6D3A2W975YNY0ASUVD9A67NER4NKS58FF0Q8G4";
        let bech32_lower = "tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4";

        for address in vec![base58, bech32_upper, bech32_lower] {
            for pj in vec![https, onion] {
                let amount = bitcoin::Amount::ONE_BTC;
                let builder = PjUriBuilder::new(
                    address.to_string(),
                    Url::from_str(pj.to_string()).unwrap(),
                    None,
                    None,
                )
                .unwrap();
                let uri = builder
                    .amount(amount.to_sat())
                    .message("message".to_string())
                    .pjos(true)
                    .label("label".to_string())
                    .build();
                // assert_eq!(uri.amount(), Some(bitcoin::Amount::ONE_BTC.to_btc()));
                print!("\n {}", uri.as_string());
            }
        }
    }
}
