//! Payjoin v1 URI functionality

use url::Url;

use super::PjParseError;
use crate::uri::error::InternalPjParseError;

/// Payjoin v1 parameter containing the endpoint URL
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PjParam(Url);

impl PjParam {
    /// Parse a new v1 PjParam from a URL
    pub(super) fn parse(url: Url) -> Result<Self, PjParseError> {
        if url.scheme() == "https"
            || url.scheme() == "http" && url.domain().unwrap_or_default().ends_with(".onion")
        {
            Ok(Self(url))
        } else {
            Err(InternalPjParseError::UnsecureEndpoint.into())
        }
    }

    /// Get the endpoint URL
    pub(crate) fn endpoint(&self) -> Url { self.0.clone() }
}

impl std::fmt::Display for PjParam {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Use the same display logic as the encapsulated child Url
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use payjoin_test_utils::BoxError;

    use super::*;
    use crate::uri::MaybePayjoinExtras;
    use crate::{OutputSubstitution, PjParam, Uri, UriExt};

    #[test]
    fn test_missing_amount() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://testnet.demo.btcpayserver.org/BTC/pj";
        assert!(Uri::try_from(uri).is_ok(), "missing amount should be ok");
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
                let uri_with_amount = format!("{address}?amount=1&pj={pj}");
                assert!(Uri::try_from(uri_with_amount).is_ok());

                let uri_without_amount = format!("{address}?pj={pj}");
                assert!(Uri::try_from(uri_without_amount).is_ok());

                let uri_shuffled_params = format!("{address}?pj={pj}&amount=1");
                assert!(Uri::try_from(uri_shuffled_params).is_ok());
            }
        }
    }

    #[test]
    fn test_supported() {
        assert!(
            Uri::try_from(
                "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.01\
                   &pjos=0&pj=HTTPS://EXAMPLE.COM/\
                   %23OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC"
            )
            .unwrap()
            .extras
            .pj_is_supported(),
            "Uri expected a success with a well formatted pj extras, but it failed"
        );
    }

    #[test]
    fn test_v1_failed_url_fragment() -> Result<(), BoxError> {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?amount=0.01\
                   &pjos=0&pj=HTTPS://EXAMPLE.COM/missing_short_id\
                   %23oh1qypm5jxyns754y4r45qwe336qfx6zr8dqgvqculvztv20tfveydmfqc";
        let extras = Uri::try_from(uri).unwrap().extras;
        match extras {
            crate::uri::MaybePayjoinExtras::Supported(extras) => {
                assert!(matches!(extras.pj_param, crate::uri::PjParam::V1(_)));
            }
            _ => panic!("Expected v1 pjparam"),
        }
        Ok(())
    }

    #[test]
    fn test_pj_duplicate_params() {
        let uri =
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pjos=1&pjos=1&pj=HTTPS://EXAMPLE.COM/\
                   %23OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC";
        let pjuri = Uri::try_from(uri);
        assert!(matches!(
            pjuri,
            Err(bitcoin_uri::de::Error::Extras(PjParseError(
                InternalPjParseError::DuplicateParams("pjos")
            )))
        ));
        let uri =
            "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pjos=1&pj=HTTPS://EXAMPLE.COM/\
                   %23OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC&pj=HTTPS://EXAMPLE.COM/\
                   %23OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC";
        let pjuri = Uri::try_from(uri);
        assert!(matches!(
            pjuri,
            Err(bitcoin_uri::de::Error::Extras(PjParseError(
                InternalPjParseError::DuplicateParams("pj")
            )))
        ));
    }

    #[test]
    fn test_serialize_pjos() {
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=HTTPS://EXAMPLE.COM/%23OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC";
        let expected_is_disabled = "pjos=0";
        let expected_is_enabled = "pjos=1";
        let mut pjuri = Uri::try_from(uri)
            .expect("Invalid uri")
            .assume_checked()
            .check_pj_supported()
            .expect("Could not parse pj extras");

        pjuri.extras.output_substitution = OutputSubstitution::Disabled;
        assert!(
            pjuri.to_string().contains(expected_is_disabled),
            "Pj uri should contain param: {expected_is_disabled}, but it did not"
        );

        pjuri.extras.output_substitution = OutputSubstitution::Enabled;
        assert!(
            !pjuri.to_string().contains(expected_is_enabled),
            "Pj uri should elide param: {expected_is_enabled}, but it did not"
        );
    }

    #[test]
    fn test_deserialize_pjos() {
        // pjos=0 should disable output substitution
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com&pjos=0";
        let parsed = Uri::try_from(uri).unwrap();
        match parsed.extras {
            MaybePayjoinExtras::Supported(extras) =>
                assert_eq!(extras.output_substitution, OutputSubstitution::Disabled),
            _ => panic!("Expected Supported PayjoinExtras"),
        }

        // pjos=1 should allow output substitution
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com&pjos=1";
        let parsed = Uri::try_from(uri).unwrap();
        match parsed.extras {
            MaybePayjoinExtras::Supported(extras) =>
                assert_eq!(extras.output_substitution, OutputSubstitution::Enabled),
            _ => panic!("Expected Supported PayjoinExtras"),
        }

        // Elided pjos=1 should allow output substitution
        let uri = "bitcoin:12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX?pj=https://example.com";
        let parsed = Uri::try_from(uri).unwrap();
        match parsed.extras {
            MaybePayjoinExtras::Supported(extras) =>
                assert_eq!(extras.output_substitution, OutputSubstitution::Enabled),
            _ => panic!("Expected Supported PayjoinExtras"),
        }
    }

    /// Test that rejects HTTP URLs that are not onion addresses
    #[test]
    fn test_http_non_onion_rejected() {
        // HTTP to regular domain should be rejected
        let url = "http://example.com";
        let result = PjParam::parse(url);
        assert!(
            matches!(result, Err(PjParseError(InternalPjParseError::UnsecureEndpoint))),
            "Expected UnsecureEndpoint error for HTTP to non-onion domain"
        );

        // HTTPS to subdomain should be accepted
        let url = "https://example.com";
        let result = PjParam::parse(url);
        assert!(
            matches!(result, Ok(PjParam::V1(_))),
            "Expected PjParam::V1 for HTTPS to non-onion domain without fragment"
        );

        // HTTP to domain ending in .onion should be accepted
        let url = "http://example.onion";
        let result = PjParam::parse(url);
        assert!(
            matches!(result, Ok(PjParam::V1(_))),
            "Expected PjParam::V1 for HTTP to onion domain without fragment"
        );
    }
}
