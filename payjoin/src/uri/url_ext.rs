use std::borrow::Cow;

use url::Url;

use crate::OhttpKeys;

/// Parse and set fragment parameters from `&pj=` URI parameter URLs
pub(crate) trait UrlExt {
    fn ohttp(&self) -> Option<OhttpKeys>;
    fn set_ohttp(&mut self, ohttp: Option<OhttpKeys>);
}

impl UrlExt for Url {
    /// Retrieve the ohttp parameter from the URL fragment
    fn ohttp(&self) -> Option<OhttpKeys> {
        use std::str::FromStr;
        if let Some(fragment) = self.fragment() {
            for param in fragment.split('&') {
                if let Some(value) = param.strip_prefix("ohttp=") {
                    let ohttp = Cow::from(value);
                    return OhttpKeys::from_str(&ohttp).ok();
                }
            }
        }
        None
    }

    /// Set the ohttp parameter in the URL fragment
    fn set_ohttp(&mut self, ohttp: Option<OhttpKeys>) {
        let mut fragment = self.fragment().unwrap_or("").to_string();
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
        self.set_fragment(if fragment.is_empty() { None } else { Some(&fragment) });
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
            Some("ohttp=AQAg3WpRjS0aqAxQUoLvpas2VYjT2oIg6-3XSiB-QiYI1BAABAABAAM")
        );

        assert_eq!(url.ohttp(), Some(ohttp_keys));

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
        assert!(uri.extras.endpoint().ohttp().is_none());
    }

    #[test]
    fn test_valid_v2_url_fragment_on_bip21() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.01\
                   &pj=https://example.com\
                   #ohttp%3DAQAg3WpRjS0aqAxQUoLvpas2VYjT2oIg6-3XSiB-QiYI1BAABAABAAM%26exp%3D1720547781";
        let uri = Uri::try_from(uri).unwrap().assume_checked().check_pj_supported().unwrap();
        assert!(uri.extras.endpoint().ohttp().is_some());
    }
}
