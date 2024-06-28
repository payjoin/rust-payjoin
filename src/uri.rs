use std::str::FromStr;

use payjoin::bitcoin::address::NetworkChecked;

use crate::error::PayjoinError;
#[cfg(not(feature = "uniffi"))]
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

impl From<payjoin::PjUriBuilder> for PjUriBuilder {
    fn from(value: payjoin::PjUriBuilder) -> Self {
        Self { inner: value }
    }
}
///Build a valid PjUri.
// Payjoin receiver can use this builder to create a payjoin uri to send to the sender.
#[cfg(not(feature = "uniffi"))]
pub struct PjUriBuilder {
    inner: payjoin::PjUriBuilder,
}
#[cfg(not(feature = "uniffi"))]
impl PjUriBuilder {
    ///Create a new PjUriBuilder with required parameters.
    pub fn new(
        address: String,
        pj: Url,
        ohttp_keys: Option<OhttpKeys>,
    ) -> Result<Self, PayjoinError> {
        let address = payjoin::bitcoin::Address::from_str(&address)?.assume_checked();
        Ok(Self { inner: payjoin::PjUriBuilder::new(address, pj.into(), ohttp_keys.map(|e| e.0)) })
    }
    ///Accepts the amount you want to receive in sats and sets it in btc .
    pub fn amount(self, amount: u64) -> Self {
        let amount = payjoin::bitcoin::Amount::from_sat(amount);
        Self { inner: self.inner.amount(amount) }
    }
    ///Set the message.
    pub fn message(self, message: String) -> Self {
        Self { inner: self.inner.message(message) }
    }
    ///Set the label.
    pub fn label(self, label: String) -> Self {
        Self { inner: self.inner.label(label) }
    }
    ///Set whether payjoin output substitution is allowed.
    pub fn pjos(self, pjos: bool) -> Self {
        Self { inner: self.inner.pjos(pjos) }
    }
    ///Constructs a Uri with PayjoinParams from the parameters set in the builder.
    pub fn build(self) -> PjUri {
        self.inner.build().into()
    }
}
#[cfg(test)]
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
                ).unwrap()
                    .amount(amount.to_sat())
                    .message("message".to_string())
                    .label("label".to_string())
                    .pjos(true);
                let uri = builder.build();
                assert_eq!(uri.amount(), Some(bitcoin::Amount::ONE_BTC.to_btc()));
             print!("\n {}", uri.as_string());
                // assert_eq!(uri.extras()disable_output_substitution, true);
                // assert_eq!(uri.extras.endpoint.to_string(), pj.to_string());
            }
        }
    }

}
