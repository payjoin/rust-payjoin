use std::str::FromStr;
use std::sync::Arc;

use payjoin::bitcoin::address::NetworkChecked;

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
    ///Gets the amount in satoshis.
    pub fn amount(&self) -> Option<u64> {
        self.0.amount.map(|x| x.to_sat())
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
pub struct PjUri(payjoin::PjUri<'static>);

impl PjUri {
    pub fn address(&self) -> String {
        self.0.clone().address.to_string()
    }
    /// Amount in sats
    pub fn amount(&self) -> Option<u64> {
        self.0.clone().amount.map(|e| e.to_sat())
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
    pub fn new(input: String) -> Result<Url, PayjoinError> {
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

#[derive(Clone)]
pub enum Kem {
    X25519Sha256 = 32,
}
impl From<Kem> for ohttp::hpke::Kem {
    fn from(value: Kem) -> Self {
        match value {
            Kem::X25519Sha256 => ohttp::hpke::Kem::X25519Sha256,
        }
    }
}
impl From<ohttp::hpke::Kem> for Kem {
    fn from(value: ohttp::hpke::Kem) -> Self {
        match value {
            ohttp::hpke::Kem::X25519Sha256 => Kem::X25519Sha256,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Copy)]
pub enum Kdf {
    HkdfSha256 = 1,
    HkdfSha384 = 2,
    HkdfSha512 = 3,
}
impl From<ohttp::hpke::Kdf> for Kdf {
    fn from(value: ohttp::hpke::Kdf) -> Self {
        match value {
            ohttp::hpke::Kdf::HkdfSha256 => Kdf::HkdfSha256,
            ohttp::hpke::Kdf::HkdfSha384 => Kdf::HkdfSha384,
            ohttp::hpke::Kdf::HkdfSha512 => Kdf::HkdfSha512,
        }
    }
}

impl From<Kdf> for ohttp::hpke::Kdf {
    fn from(value: Kdf) -> Self {
        match value {
            Kdf::HkdfSha256 => ohttp::hpke::Kdf::HkdfSha256,
            Kdf::HkdfSha384 => ohttp::hpke::Kdf::HkdfSha384,
            Kdf::HkdfSha512 => ohttp::hpke::Kdf::HkdfSha512,
        }
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Copy)]
pub enum Aead {
    Aes128Gcm = 1,
    Aes256Gcm = 2,
    ChaCha20Poly1305 = 3,
}

impl From<Aead> for ohttp::hpke::Aead {
    fn from(value: Aead) -> Self {
        match value {
            Aead::Aes128Gcm => ohttp::hpke::Aead::Aes128Gcm,
            Aead::Aes256Gcm => ohttp::hpke::Aead::Aes256Gcm,
            Aead::ChaCha20Poly1305 => ohttp::hpke::Aead::ChaCha20Poly1305,
        }
    }
}

impl From<ohttp::hpke::Aead> for Aead {
    fn from(value: ohttp::hpke::Aead) -> Self {
        match value {
            ohttp::hpke::Aead::Aes128Gcm => Aead::Aes128Gcm,
            ohttp::hpke::Aead::Aes256Gcm => Aead::Aes256Gcm,
            ohttp::hpke::Aead::ChaCha20Poly1305 => Aead::ChaCha20Poly1305,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SymmetricSuite {
    pub kdf: Kdf,
    pub aead: Aead,
}
impl From<&SymmetricSuite> for ohttp::SymmetricSuite {
    fn from(value: &SymmetricSuite) -> Self {
        ohttp::SymmetricSuite::new(value.kdf.clone().into(), value.aead.into())
    }
}

impl From<ohttp::SymmetricSuite> for SymmetricSuite {
    fn from(value: ohttp::SymmetricSuite) -> Self {
        SymmetricSuite { kdf: value.kdf().into(), aead: value.aead().clone().into() }
    }
}

#[derive(Clone)]
pub struct KeyConfig(Arc<ohttp::KeyConfig>);
impl From<ohttp::KeyConfig> for KeyConfig {
    fn from(value: ohttp::KeyConfig) -> Self {
        Self(Arc::new(value))
    }
}

impl From<KeyConfig> for ohttp::KeyConfig {
    fn from(value: KeyConfig) -> Self {
        (*value.0).clone()
    }
}

#[allow(dead_code)]
impl KeyConfig {
    fn new(
        key_id: u8,
        kem: Kem,
        symmetric: Vec<SymmetricSuite>,
    ) -> Result<KeyConfig, PayjoinError> {
        ohttp::KeyConfig::new(key_id, kem.into(), symmetric.iter().map(|s| s.into()).collect())
            .map(|k| k.into())
            .map_err(|e| e.into())
    }
    /// Encode into a wire format.  This shares a format with the core of ECH:
    ///
    /// ```tls-format
    /// opaque HpkePublicKey[Npk];
    /// uint16 HpkeKemId;  // Defined in I-D.irtf-cfrg-hpke
    /// uint16 HpkeKdfId;  // Defined in I-D.irtf-cfrg-hpke
    /// uint16 HpkeAeadId; // Defined in I-D.irtf-cfrg-hpke
    ///
    /// struct {
    ///   HpkeKdfId kdf_id;
    ///   HpkeAeadId aead_id;
    /// } ECHCipherSuite;
    ///
    /// struct {
    ///   uint8 key_id;
    ///   HpkeKemId kem_id;
    ///   HpkePublicKey public_key;
    ///   ECHCipherSuite cipher_suites<4..2^16-4>;
    /// } ECHKeyConfig;
    /// ```
    /// # Panics
    /// Not as a result of this function.
    pub fn encode(&self) -> Result<Vec<u8>, PayjoinError> {
        self.0.encode().map(|k| k).map_err(|e| e.into())
    }
    ///Construct a configuration from the encoded server configuration. The format of encoded_config is the output of Self::encode.
    pub fn decode(encoded_config: Vec<u8>) -> Result<KeyConfig, PayjoinError> {
        ohttp::KeyConfig::decode(encoded_config.as_slice()).map(|k| k.into()).map_err(|e| e.into())
    }
    ///Decode a list of key configurations. This only returns the valid and supported key configurations; unsupported configurations are dropped silently.
    pub fn decode_list(encoded_list: Vec<u8>) -> Result<Vec<KeyConfig>, PayjoinError> {
        ohttp::KeyConfig::decode_list(encoded_list.as_slice())
            .map(|k| k.iter().map(|e| e.clone().into()).collect())
            .map_err(|e| e.into())
    }
}

/// Build a valid `PjUri`.
///
/// Payjoin receiver can use this builder to create a payjoin
/// uri to send to the sender.
#[derive(Clone)]
#[allow(dead_code)]
pub struct PjUriBuilder {
    /// Address you want to receive funds to.
    address: String,
    /// Amount you want to receive.
    ///
    /// If `None` the amount will be left unspecified.
    amount: Option<u64>,
    /// Message
    message: Option<String>,
    /// Label
    label: Option<String>,
    /// Payjoin endpoint url listening for payjoin requests.
    pj: Url,
    /// Whether or not payjoin output substitution is allowed
    pjos: bool,
    /// Required only for v2 payjoin.
    ohttp: Option<KeyConfig>,
}

impl PjUriBuilder {
    /// Create a new `PjUriBuilder` with required parameters.
    pub fn new(address: String, pj: Url, ohttp_config: Option<KeyConfig>) -> Self {
        Self {
            address,
            amount: None,
            message: None,
            label: None,
            pj,
            pjos: false,
            ohttp: ohttp_config,
        }
    }

    /// Set the amount you want to receive.
    pub fn amount(&self, amount: u64) -> Arc<PjUriBuilder> {
        Arc::new(Self { amount: Some(amount), ..self.clone() })
    }

    /// Set the message.
    pub fn message(&self, message: String) -> Arc<PjUriBuilder> {
        Arc::new(Self { message: Some(message), ..self.clone() })
    }

    /// Set the label.
    pub fn label(&self, label: String) -> Arc<PjUriBuilder> {
        Arc::new(Self { label: Some(label), ..self.clone() })
    }

    /// Set whether or not payjoin output substitution is allowed.
    pub fn pjos(&self, pjos: bool) -> Arc<PjUriBuilder> {
        Arc::new(Self { pjos: pjos, ..self.clone() })
    }

    //TODO; Implement Copy to PjUriBuilder
    // Build payjoin URI.
    //
    // Constructs a `bip21::Uri` with PayjoinParams from the
    //  parameters set in the builder.
    // pub fn build(&self) -> Result<PjUri, PayjoinError> {
    //  let builder = payjoin::PjUriBuilder::new(payjoin::bitcoin::address::Address::from_str(self.address.as_str())?.assume_checked(),
    //                                           self.pj.clone().into(), self.ohttp.clone().map(|e| e.into())).borrow_mut();
    //     if let Some(amount) = self.amount.clone() {
    //         builder.amount(payjoin::bitcoin::Amount::from_sat(amount.clone())).pjos(self.pjos);
    //     }
    //     if let Some(message) = self.message.clone() {
    //         builder.message(message);
    //     }
    //     if let Some(label) = self.label.clone() {
    //         builder.label(label);
    //     }
    //     if self.pjos {
    //         builder.pjos(self.pjos.clone());
    //     }
    //
    //   Ok(builder.build().into())
    // }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use payjoin::Uri;

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
                let uri = format!("{}?amount=1&pj={}", address, pj);
                assert!(Uri::try_from(&*uri).is_ok());
            }
        }
    }

    #[test]
    fn test_unsupported() {
        assert!(!Uri::try_from("bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX")
            .unwrap()
            .extras
            .pj_is_supported());
    }
}
