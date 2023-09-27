use crate::{
    error::PayjoinError,
    send::{ Configuration, Context, Request },
    transaction::PartiallySignedTransaction,
    Address,
};
use payjoin::{ bitcoin::address::NetworkChecked, PjUriExt, UriExt };
use std::{ str::FromStr, sync::Arc };

pub struct PrjUriRequest {
    pub request: Request,
    pub context: Arc<Context>,
}

#[derive(Clone)]
pub struct Uri {
    internal: payjoin::Uri<'static, NetworkChecked>,
}
impl From<Uri> for payjoin::Uri<'static, NetworkChecked> {
    fn from(value: Uri) -> Self {
        value.internal
    }
}
impl From<payjoin::Uri<'static, NetworkChecked>> for Uri {
    fn from(value: payjoin::Uri<'static, NetworkChecked>) -> Self {
        Self { internal: value }
    }
}
impl Uri {
    pub fn new(uri: String) -> Result<Self, PayjoinError> {
        match payjoin::Uri::from_str(uri.as_str()) {
            Ok(e) => Ok(Uri { internal: e.assume_checked() }),
            Err(e) => Err(PayjoinError::PjParseError { message: e.to_string() }),
        }
    }
    //TODO; ADD TO .UDL
    pub fn address(&self) -> Arc<Address> {
        Arc::new(Address { internal: self.internal.clone().address })
    }
    pub fn amount(&self) -> Option<u64> {
        self.internal.amount.map(|x| x.to_sat())
    }
    pub fn check_pj_supported(&self) -> Result<Arc<PrjUri>, PayjoinError> {
        match self.internal.clone().check_pj_supported() {
            Ok(e) => Ok(Arc::new(PrjUri { internal: e })),
            Err(e) => Err(PayjoinError::PjNotSupported { message: e.to_string() }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PrjUri {
    internal: payjoin::PjUri<'static>,
}
impl From<PrjUri> for payjoin::PjUri<'static> {
    fn from(value: PrjUri) -> Self {
        value.internal
    }
}
impl From<payjoin::PjUri<'static>> for PrjUri {
    fn from(value: payjoin::PjUri<'static>) -> Self {
        Self { internal: value }
    }
}

impl PrjUri {
    pub fn create_pj_request(
        &self,
        psbt: Arc<PartiallySignedTransaction>,
        params: Arc<Configuration>
    ) -> Result<PrjUriRequest, PayjoinError> {
        let config = params.get_configuration();
        match self.internal.clone().create_pj_request((*psbt).clone().into(), config.0.unwrap()) {
            Ok(e) =>
                Ok(PrjUriRequest {
                    request: Request { url: Arc::new(Url { internal: e.0.url }), body: e.0.body },
                    context: Arc::new(e.1.into()),
                }),
            Err(e) => Err(PayjoinError::CreateRequestError { message: e.to_string() }),
        }
    }

    pub fn address(&self) -> Arc<Address> {
        Arc::new(self.internal.address.clone().into())
    }
    pub fn amount(&self) -> Option<Arc<Amount>> {
        self.internal.amount.map(|x| Arc::new(Amount::from_sat(x.to_sat())))
    }
}
#[derive(Clone, Debug)]
pub struct Amount {
    internal: u64,
}
impl Amount {
    pub fn from_sat(sats: u64) -> Self {
        Self { internal: sats }
    }
    pub fn from_btc(btc: f64) -> Self {
        Self { internal: (btc as u64) * 100000000 }
    }
    pub fn to_sat(&self) -> u64 {
        self.internal
    }
    pub fn to_btc(&self) -> f64 {
        return (self.internal as f64) / (100000000 as f64);
    }
}

pub struct Url {
    internal: url::Url,
}
impl Url {
    pub fn new(input: String) -> Result<Url, PayjoinError> {
        match url::Url::from_str(input.as_str()) {
            Ok(e) => Ok(Self { internal: e }),
            Err(e) => Err(PayjoinError::UnexpectedError { message: e.to_string() }),
        }
    }
    pub fn query(&self) -> Option<String> {
        self.internal.query().map(|x| x.to_string())
    }
}
#[cfg(test)]
mod tests {
    use payjoin::Uri;
    use std::convert::TryFrom;

    #[test]
    fn test_short() {
        assert!(Uri::try_from("").is_err());
        assert!(Uri::try_from("bitcoin").is_err());
        assert!(Uri::try_from("bitcoin:").is_err());
    }

    #[ignore]
    #[test]
    fn test_todo_url_encoded() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=https://example.com?ciao";
        assert!(Uri::try_from(uri).is_err(), "pj url should be url encoded");
    }

    #[test]
    fn test_valid_url() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=this_is_NOT_a_validURL";
        assert!(Uri::try_from(uri).is_err(), "pj is not a valid url");
    }

    #[test]
    fn test_missing_amount() {
        let uri =
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://testnet.demo.btcpayserver.org/BTC/pj";
        assert!(Uri::try_from(uri).is_ok(), "missing amount should be ok");
    }

    #[test]
    fn test_unencrypted() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=http://example.com";
        assert!(Uri::try_from(uri).is_err(), "unencrypted connection");

        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=1&pj=ftp://foo.onion";
        assert!(Uri::try_from(uri).is_err(), "unencrypted connection");
    }

    #[test]
    fn test_valid_uris() {
        let https = "https://example.com";
        let onion = "http://vjdpwgybvubne5hda6v4c5iaeeevhge6jvo3w2cl6eocbwwvwxp7b7qd.onion";

        let base58 = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX";
        let bech32_upper = "BITCOIN:TB1Q6D3A2W975YNY0ASUVD9A67NER4NKS58FF0Q8G4";
        let bech32_lower = "bitcoin:tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4";

        for address in [base58, bech32_upper, bech32_lower].iter() {
            for pj in [https, onion].iter() {
                // TODO add with and without amount
                // TODO shuffle params
                let uri = format!("{}?amount=1&pj={}", address, pj);
                assert!(Uri::try_from(&*uri).is_ok());
            }
        }
    }

    #[test]
    fn test_unsupported() {
        assert!(
            !Uri::try_from("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX")
                .unwrap()
                .extras.pj_is_supported()
        );
    }
}
