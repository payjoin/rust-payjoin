use std::borrow::Cow;

use percent_encoding::{AsciiSet, PercentDecodeError, CONTROLS};
use url::Url;

use crate::OhttpKeys;

/// Parse and set fragment parameters from `&pj=` URI parameter URLs
pub(crate) trait UrlExt {
    fn ohttp(&self) -> Result<Option<OhttpKeys>, PercentDecodeError>;
    fn set_ohttp(&mut self, ohttp: Option<OhttpKeys>) -> Result<(), PercentDecodeError>;
}

// Characters '=' and '&' conflict with BIP21 URI parameters and must be percent-encoded
const BIP21_CONFLICTING: &AsciiSet = &CONTROLS.add(b'=').add(b'&');

impl UrlExt for Url {
    /// Retrieve the ohttp parameter from the URL fragment
    fn ohttp(&self) -> Result<Option<OhttpKeys>, PercentDecodeError> {
        use std::str::FromStr;
        if let Some(fragment) = self.fragment() {
            let decoded_fragment =
                percent_encoding::percent_decode_str(fragment)?.decode_utf8_lossy();
            for param in decoded_fragment.split('&') {
                if let Some(value) = param.strip_prefix("ohttp=") {
                    let ohttp = Cow::from(value);
                    return Ok(OhttpKeys::from_str(&ohttp).ok());
                }
            }
        }
        Ok(None)
    }

    /// Set the ohttp parameter in the URL fragment
    fn set_ohttp(&mut self, ohttp: Option<OhttpKeys>) -> Result<(), PercentDecodeError> {
        let fragment = self.fragment().unwrap_or("").to_string();
        let mut fragment =
            percent_encoding::percent_decode_str(&fragment)?.decode_utf8_lossy().to_string();
        if let Some(start) = fragment.find("ohttp=") {
            let end = fragment[start..].find('&').map_or(fragment.len(), |i| start + i);
            fragment.replace_range(start..end, "");
            if fragment.ends_with('&') {
                fragment.pop();
            }
        }
        if let Some(ohttp) = ohttp {
            let new_ohttp = format!("ohttp={}", ohttp);
            if !fragment.is_empty() {
                fragment.push('&');
            }
            fragment.push_str(&new_ohttp);
        }
        let encoded_fragment =
            percent_encoding::utf8_percent_encode(&fragment, BIP21_CONFLICTING).to_string();
        self.set_fragment(if encoded_fragment.is_empty() { None } else { Some(&encoded_fragment) });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use url::Url;

    use super::*;
    use crate::{Uri, UriExt};

    #[test]
    fn test_ohttp_get_set() {
        let mut url = Url::parse("https://example.com").unwrap();

        let ohttp_keys =
            OhttpKeys::from_str("AQAg3WpRjS0aqAxQUoLvpas2VYjT2oIg6-3XSiB-QiYI1BAABAABAAM").unwrap();
        let _ = url.set_ohttp(Some(ohttp_keys.clone()));
        assert_eq!(
            url.fragment(),
            Some("ohttp%3DAQAg3WpRjS0aqAxQUoLvpas2VYjT2oIg6-3XSiB-QiYI1BAABAABAAM")
        );

        let retrieved_ohttp = url.ohttp().unwrap();
        assert_eq!(retrieved_ohttp, Some(ohttp_keys));

        let _ = url.set_ohttp(None);
        assert_eq!(url.fragment(), None);
    }

    #[test]
    fn test_invalid_v2_url_fragment_on_bip21() {
        // fragment is not percent encoded so `&ohttp=` is parsed as a query parameter, not a fragment parameter
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.01\
                   &pj=https://example.com\
                   #exp=1720547781&ohttp=AQAg3WpRjS0aqAxQUoLvpas2VYjT2oIg6-3XSiB-QiYI1BAABAABAAM";
        let uri = Uri::try_from(uri).unwrap().assume_checked().check_pj_supported().unwrap();
        assert!(uri.extras.endpoint().ohttp().unwrap().is_none());
    }

    #[test]
    fn test_valid_v2_url_fragment_on_bip21() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.01\
                   &pj=https://example.com\
                   #ohttp%3DAQAg3WpRjS0aqAxQUoLvpas2VYjT2oIg6-3XSiB-QiYI1BAABAABAAM%26exp%3D1720547781";
        let uri = Uri::try_from(uri).unwrap().assume_checked().check_pj_supported().unwrap();
        assert!(uri.extras.endpoint().ohttp().unwrap().is_some());
    }
}
