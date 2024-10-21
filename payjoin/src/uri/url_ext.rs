use std::str::FromStr;

use bitcoin::bech32::Hrp;
use bitcoin::consensus::encode::Decodable;
use bitcoin::consensus::Encodable;
use url::Url;

use super::error::ParseReceiverPubkeyError;
use crate::hpke::HpkePublicKey;
use crate::OhttpKeys;

/// Parse and set fragment parameters from `&pj=` URI parameter URLs
pub(crate) trait UrlExt {
    fn receiver_pubkey(&self) -> Result<HpkePublicKey, ParseReceiverPubkeyError>;
    fn set_receiver_pubkey(&mut self, exp: HpkePublicKey);
    fn ohttp(&self) -> Option<OhttpKeys>;
    fn set_ohttp(&mut self, ohttp: OhttpKeys);
    fn exp(&self) -> Option<std::time::SystemTime>;
    fn set_exp(&mut self, exp: std::time::SystemTime);
}

impl UrlExt for Url {
    /// Retrieve the receiver's public key from the URL fragment
    fn receiver_pubkey(&self) -> Result<HpkePublicKey, ParseReceiverPubkeyError> {
        let value = get_param(self, "RK1", |v| Some(v.to_owned()))
            .ok_or(ParseReceiverPubkeyError::MissingPubkey)?;

        let (hrp, bytes) = crate::bech32::nochecksum::decode(&value)
            .map_err(ParseReceiverPubkeyError::DecodeBech32)?;

        let rk_hrp: Hrp = Hrp::parse("RK").unwrap();
        if hrp != rk_hrp {
            return Err(ParseReceiverPubkeyError::InvalidHrp(hrp));
        }

        HpkePublicKey::from_compressed_bytes(&bytes[..])
            .map_err(ParseReceiverPubkeyError::InvalidPubkey)
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
    fn ohttp(&self) -> Option<OhttpKeys> {
        get_param(self, "OH1", |value| OhttpKeys::from_str(value).ok())
    }

    /// Set the ohttp parameter in the URL fragment
    fn set_ohttp(&mut self, ohttp: OhttpKeys) { set_param(self, "OH1", &ohttp.to_string()) }

    /// Retrieve the exp parameter from the URL fragment
    fn exp(&self) -> Option<std::time::SystemTime> {
        get_param(self, "EX1", |value| {
            let (hrp, bytes) = crate::bech32::nochecksum::decode(value).ok()?;

            let ex_hrp: Hrp = Hrp::parse("EX").unwrap();
            if hrp != ex_hrp {
                return None;
            }

            let mut cursor = &bytes[..];
            u32::consensus_decode(&mut cursor)
                .map(|timestamp| {
                    std::time::UNIX_EPOCH + std::time::Duration::from_secs(timestamp as u64)
                })
                .ok()
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Uri, UriExt};

    #[test]
    fn test_ohttp_get_set() {
        let mut url = Url::parse("https://example.com").unwrap();

        let serialized = "OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC";
        let ohttp_keys = OhttpKeys::from_str(serialized).unwrap();
        url.set_ohttp(ohttp_keys.clone());

        assert_eq!(url.fragment(), Some(serialized));
        assert_eq!(url.ohttp(), Some(ohttp_keys));
    }

    #[test]
    fn test_exp_get_set() {
        let mut url = Url::parse("https://example.com").unwrap();

        let exp_time =
            std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1720547781);
        url.set_exp(exp_time);
        assert_eq!(url.fragment(), Some("EX1C4UC6ES"));

        assert_eq!(url.exp(), Some(exp_time));
    }

    #[test]
    fn test_valid_v2_url_fragment_on_bip21() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.01\
                   &pjos=0&pj=HTTPS://EXAMPLE.COM/\
                   %23OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC";
        let pjuri = Uri::try_from(uri).unwrap().assume_checked().check_pj_supported().unwrap();
        assert!(pjuri.extras.endpoint().ohttp().is_some());
        assert_eq!(format!("{}", pjuri), uri);

        let reordered = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.01\
                   &pj=HTTPS://EXAMPLE.COM/\
                   %23OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC\
                   &pjos=0";
        let pjuri =
            Uri::try_from(reordered).unwrap().assume_checked().check_pj_supported().unwrap();
        assert!(pjuri.extras.endpoint().ohttp().is_some());
        assert_eq!(format!("{}", pjuri), uri);
    }
}
