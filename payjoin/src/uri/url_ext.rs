use std::str::FromStr;

use bitcoin::bech32::Hrp;
use bitcoin::consensus::encode::Decodable;
use bitcoin::consensus::Encodable;
use url::Url;

use super::error::BadEndpointError;
use crate::hpke::HpkePublicKey;
use crate::ohttp::OhttpKeys;

/// Parse and set fragment parameters from `&pj=` URI parameter URLs
pub(crate) trait UrlExt {
    fn receiver_pubkey(&self) -> Result<HpkePublicKey, ParseReceiverPubkeyParamError>;
    fn set_receiver_pubkey(&mut self, exp: HpkePublicKey);
    fn ohttp(&self) -> Result<OhttpKeys, ParseOhttpKeysParamError>;
    fn set_ohttp(&mut self, ohttp: OhttpKeys);
    fn exp(&self) -> Result<std::time::SystemTime, ParseExpParamError>;
    fn set_exp(&mut self, exp: std::time::SystemTime);
}

impl UrlExt for Url {
    /// Retrieve the receiver's public key from the URL fragment
    fn receiver_pubkey(&self) -> Result<HpkePublicKey, ParseReceiverPubkeyParamError> {
        let value = get_param(self, "RK1", |v| Some(v.to_owned()))
            .ok_or(ParseReceiverPubkeyParamError::MissingPubkey)?;

        let (hrp, bytes) = crate::bech32::nochecksum::decode(&value)
            .map_err(ParseReceiverPubkeyParamError::DecodeBech32)?;

        let rk_hrp: Hrp = Hrp::parse("RK").unwrap();
        if hrp != rk_hrp {
            return Err(ParseReceiverPubkeyParamError::InvalidHrp(hrp));
        }

        HpkePublicKey::from_compressed_bytes(&bytes[..])
            .map_err(ParseReceiverPubkeyParamError::InvalidPubkey)
    }

    /// Set the receiver's public key in the URL fragment
    fn set_receiver_pubkey(&mut self, pubkey: HpkePublicKey) {
        let rk_hrp: Hrp = Hrp::parse("RK").unwrap();

        set_param(
            self,
            "RK1",
            &crate::bech32::nochecksum::encode(rk_hrp, &pubkey.to_compressed_bytes())
                .expect("encoding compressed pubkey bytes should never fail"),
        )
    }

    /// Retrieve the ohttp parameter from the URL fragment
    fn ohttp(&self) -> Result<OhttpKeys, ParseOhttpKeysParamError> {
        let value = get_param(self, "OH1", |v| Some(v.to_owned()))
            .ok_or(ParseOhttpKeysParamError::MissingOhttpKeys)?;
        OhttpKeys::from_str(&value).map_err(ParseOhttpKeysParamError::InvalidOhttpKeys)
    }

    /// Set the ohttp parameter in the URL fragment
    fn set_ohttp(&mut self, ohttp: OhttpKeys) { set_param(self, "OH1", &ohttp.to_string()) }

    /// Retrieve the exp parameter from the URL fragment
    fn exp(&self) -> Result<std::time::SystemTime, ParseExpParamError> {
        let value =
            get_param(self, "EX1", |v| Some(v.to_owned())).ok_or(ParseExpParamError::MissingExp)?;

        let (hrp, bytes) =
            crate::bech32::nochecksum::decode(&value).map_err(ParseExpParamError::DecodeBech32)?;

        let ex_hrp: Hrp = Hrp::parse("EX").unwrap();
        if hrp != ex_hrp {
            return Err(ParseExpParamError::InvalidHrp(hrp));
        }

        u32::consensus_decode(&mut &bytes[..])
            .map(|timestamp| {
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp as u64)
            })
            .map_err(ParseExpParamError::InvalidExp)
    }

    /// Set the exp parameter in the URL fragment
    fn set_exp(&mut self, exp: std::time::SystemTime) {
        let t = match exp.duration_since(std::time::UNIX_EPOCH) {
            Ok(duration) => duration.as_secs().try_into().unwrap(), // TODO Result type instead of Option & unwrap
            Err(_) => 0u32,
        };

        let mut buf = [0u8; 4];
        t.consensus_encode(&mut &mut buf[..]).unwrap(); // TODO no unwrap

        let ex_hrp: Hrp = Hrp::parse("EX").unwrap();

        let exp_str = crate::bech32::nochecksum::encode(ex_hrp, &buf)
            .expect("encoding u32 timestamp should never fail");

        set_param(self, "EX1", &exp_str)
    }
}

pub fn parse_with_fragment(endpoint: &str) -> Result<Url, BadEndpointError> {
    let url = Url::parse(endpoint).map_err(BadEndpointError::UrlParse)?;

    if let Some(fragment) = url.fragment() {
        if fragment.chars().any(|c| c.is_lowercase()) {
            return Err(BadEndpointError::LowercaseFragment);
        }
    };
    Ok(url)
}

fn get_param<F, T>(url: &Url, prefix: &str, parse: F) -> Option<T>
where
    F: Fn(&str) -> Option<T>,
{
    if let Some(fragment) = url.fragment() {
        for param in fragment.split('+') {
            if param.starts_with(prefix) {
                return parse(param);
            }
        }
    }
    None
}

fn set_param(url: &mut Url, prefix: &str, param: &str) {
    let fragment = url.fragment().unwrap_or("");
    let mut fragment = fragment.to_string();
    if let Some(start) = fragment.find(prefix) {
        let end = fragment[start..].find('+').map_or(fragment.len(), |i| start + i);
        fragment.replace_range(start..end, "");
        if fragment.ends_with('+') {
            fragment.pop();
        }
    }

    if !fragment.is_empty() {
        fragment.push('+');
    }
    fragment.push_str(param);

    url.set_fragment(if fragment.is_empty() { None } else { Some(&fragment) });
}

#[cfg(feature = "v2")]
#[derive(Debug)]
pub(crate) enum ParseOhttpKeysParamError {
    MissingOhttpKeys,
    InvalidOhttpKeys(crate::ohttp::ParseOhttpKeysError),
}

#[cfg(feature = "v2")]
impl std::fmt::Display for ParseOhttpKeysParamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ParseOhttpKeysParamError::*;

        match &self {
            MissingOhttpKeys => write!(f, "ohttp keys are missing"),
            InvalidOhttpKeys(o) => write!(f, "invalid ohttp keys: {}", o),
        }
    }
}

#[cfg(feature = "v2")]
#[derive(Debug)]
pub(crate) enum ParseExpParamError {
    MissingExp,
    InvalidHrp(bitcoin::bech32::Hrp),
    DecodeBech32(bitcoin::bech32::primitives::decode::CheckedHrpstringError),
    InvalidExp(bitcoin::consensus::encode::Error),
}

#[cfg(feature = "v2")]
impl std::fmt::Display for ParseExpParamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ParseExpParamError::*;

        match &self {
            MissingExp => write!(f, "exp is missing"),
            InvalidHrp(h) => write!(f, "incorrect hrp for exp: {}", h),
            DecodeBech32(d) => write!(f, "exp is not valid bech32: {}", d),
            InvalidExp(i) =>
                write!(f, "exp param does not contain a bitcoin consensus encoded u32: {}", i),
        }
    }
}

#[cfg(feature = "v2")]
#[derive(Debug)]
pub(crate) enum ParseReceiverPubkeyParamError {
    MissingPubkey,
    InvalidHrp(bitcoin::bech32::Hrp),
    DecodeBech32(bitcoin::bech32::primitives::decode::CheckedHrpstringError),
    InvalidPubkey(crate::hpke::HpkeError),
}

#[cfg(feature = "v2")]
impl std::fmt::Display for ParseReceiverPubkeyParamError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use ParseReceiverPubkeyParamError::*;

        match &self {
            MissingPubkey => write!(f, "receiver public key is missing"),
            InvalidHrp(h) => write!(f, "incorrect hrp for receiver key: {}", h),
            DecodeBech32(e) => write!(f, "receiver public is not valid base64: {}", e),
            InvalidPubkey(e) =>
                write!(f, "receiver public key does not represent a valid pubkey: {}", e),
        }
    }
}

#[cfg(feature = "v2")]
impl std::error::Error for ParseReceiverPubkeyParamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParseReceiverPubkeyParamError::*;

        match &self {
            MissingPubkey => None,
            InvalidHrp(_) => None,
            DecodeBech32(error) => Some(error),
            InvalidPubkey(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use payjoin_test_utils::BoxError;

    use super::*;
    use crate::{Uri, UriExt};

    #[test]
    fn test_ohttp_get_set() {
        let mut url = Url::parse("https://example.com").unwrap();

        let serialized = "OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC";
        let ohttp_keys = OhttpKeys::from_str(serialized).unwrap();
        url.set_ohttp(ohttp_keys.clone());

        assert_eq!(url.fragment(), Some(serialized));
        assert_eq!(url.ohttp().unwrap(), ohttp_keys);
    }

    #[test]
    fn test_errors_when_parsing_ohttp() {
        let missing_ohttp_url = Url::parse("https://example.com").unwrap();
        assert!(matches!(
            missing_ohttp_url.ohttp(),
            Err(ParseOhttpKeysParamError::MissingOhttpKeys)
        ));

        let invalid_ohttp_url =
            Url::parse("https://example.com?pj=https://test-payjoin-url#OH1invalid_bech_32")
                .unwrap();
        assert!(matches!(
            invalid_ohttp_url.ohttp(),
            Err(ParseOhttpKeysParamError::InvalidOhttpKeys(_))
        ));
    }

    #[test]
    fn test_exp_get_set() {
        let mut url = Url::parse("https://example.com").unwrap();

        let exp_time =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1720547781);
        url.set_exp(exp_time);
        assert_eq!(url.fragment(), Some("EX1C4UC6ES"));

        assert_eq!(url.exp().unwrap(), exp_time);
    }

    #[test]
    fn test_errors_when_parsing_exp() {
        let missing_exp_url = Url::parse("http://example.com").unwrap();
        assert!(matches!(missing_exp_url.exp(), Err(ParseExpParamError::MissingExp)));

        let invalid_bech32_exp_url =
            Url::parse("http://example.com?pj=https://test-payjoin-url#EX1invalid_bech_32")
                .unwrap();
        assert!(matches!(invalid_bech32_exp_url.exp(), Err(ParseExpParamError::DecodeBech32(_))));

        // Since the HRP is everything to the left of the right-most separator, the invalid url in
        // this test would have it's HRP being parsed as EX101 instead of the expected EX1
        let invalid_hrp_exp_url =
            Url::parse("http://example.com?pj=https://test-payjoin-url#EX1010").unwrap();
        assert!(matches!(invalid_hrp_exp_url.exp(), Err(ParseExpParamError::InvalidHrp(_))));

        // Not enough data to decode into a u32
        let invalid_timestamp_exp_url =
            Url::parse("http://example.com?pj=https://test-payjoin-url#EX10").unwrap();
        assert!(matches!(invalid_timestamp_exp_url.exp(), Err(ParseExpParamError::InvalidExp(_))))
    }

    #[test]
    fn test_valid_v2_url_fragment_on_bip21() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.01\
                   &pjos=0&pj=HTTPS://EXAMPLE.COM/\
                   %23OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC";
        let pjuri = Uri::try_from(uri).unwrap().assume_checked().check_pj_supported().unwrap();
        assert!(pjuri.extras.endpoint().ohttp().is_ok());
        assert_eq!(format!("{}", pjuri), uri);

        let reordered = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.01\
                   &pj=HTTPS://EXAMPLE.COM/\
                   %23OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC\
                   &pjos=0";
        let pjuri =
            Uri::try_from(reordered).unwrap().assume_checked().check_pj_supported().unwrap();
        assert!(pjuri.extras.endpoint().ohttp().is_ok());
        assert_eq!(format!("{}", pjuri), uri);
    }

    #[test]
    fn test_failed_url_fragment() -> Result<(), BoxError> {
        let expected_error = "LowercaseFragment";
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.01\
                   &pjos=0&pj=HTTPS://EXAMPLE.COM/\
                   %23oh1qypm5jxyns754y4r45qwe336qfx6zr8dqgvqculvztv20tfveydmfqc";
        assert!(Uri::try_from(uri).is_err(), "Expected url fragment failure, but it succeeded");
        if let Err(bitcoin_uri::de::Error::Extras(error)) = Uri::try_from(uri) {
            assert!(
                error.to_string().contains(expected_error),
                "Error should indicate '{}' but was: {}",
                expected_error,
                error
            );
        }
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.01\
                   &pjos=0&pj=HTTPS://EXAMPLE.COM/\
                   %23OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQc";
        assert!(Uri::try_from(uri).is_err(), "Expected url fragment failure, but it succeeded");
        if let Err(bitcoin_uri::de::Error::Extras(error)) = Uri::try_from(uri) {
            assert!(
                error.to_string().contains(expected_error),
                "Error should indicate '{}' but was: {}",
                expected_error,
                error
            );
        }
        Ok(())
    }
}
