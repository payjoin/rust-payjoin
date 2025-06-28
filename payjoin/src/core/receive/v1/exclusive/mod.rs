mod error;
pub(crate) use error::InternalRequestError;
pub use error::RequestError;

use super::*;
use crate::into_url::IntoUrl;
use crate::Version;

const SUPPORTED_VERSIONS: &[Version] = &[Version::One];

pub trait Headers {
    fn get_header(&self, key: &str) -> Option<&str>;
}

pub fn build_v1_pj_uri<'a>(
    address: &bitcoin::Address,
    endpoint: impl IntoUrl,
    output_substitution: OutputSubstitution,
) -> Result<crate::uri::PjUri<'a>, crate::into_url::Error> {
    let extras = crate::uri::PayjoinExtras { endpoint: endpoint.into_url()?, output_substitution };
    Ok(bitcoin_uri::Uri::with_extras(address.clone(), extras))
}

impl UncheckedProposal {
    pub fn from_request(
        body: &[u8],
        query: &str,
        headers: impl Headers,
    ) -> Result<Self, ReplyableError> {
        let validated_body = validate_body(headers, body).map_err(ReplyableError::V1)?;

        let base64 = std::str::from_utf8(validated_body).map_err(InternalPayloadError::Utf8)?;

        let (psbt, params) = crate::receive::parse_payload(base64, query, SUPPORTED_VERSIONS)
            .map_err(ReplyableError::Payload)?;

        Ok(UncheckedProposal { psbt, params })
    }
}

/// Validate the request headers for a Payjoin request
///
/// [`RequestError`] should only be produced here.
fn validate_body(headers: impl Headers, body: &[u8]) -> Result<&[u8], RequestError> {
    let content_type = headers
        .get_header("content-type")
        .ok_or(InternalRequestError::MissingHeader("Content-Type"))?;
    if !content_type.starts_with("text/plain") {
        return Err(InternalRequestError::InvalidContentType(content_type.to_owned()).into());
    }

    let content_length = headers
        .get_header("content-length")
        .ok_or(InternalRequestError::MissingHeader("Content-Length"))?
        .parse::<usize>()
        .map_err(InternalRequestError::InvalidContentLength)?;
    if body.len() != content_length {
        return Err(InternalRequestError::ContentLengthMismatch {
            expected: content_length,
            actual: body.len(),
        }
        .into());
    }

    Ok(body)
}

#[cfg(test)]
mod tests {
    use bitcoin::{Address, AddressType};
    use payjoin_test_utils::{ORIGINAL_PSBT, QUERY_PARAMS};

    use super::*;

    #[derive(Debug, Clone)]
    struct MockHeaders {
        length: String,
    }

    impl MockHeaders {
        fn new(length: u64) -> MockHeaders { MockHeaders { length: length.to_string() } }
    }

    impl Headers for MockHeaders {
        fn get_header(&self, key: &str) -> Option<&str> {
            match key {
                "content-length" => Some(&self.length),
                "content-type" => Some("text/plain"),
                _ => None,
            }
        }
    }

    #[test]
    fn test_parse_body() {
        let body = ORIGINAL_PSBT.as_bytes().to_vec();
        let headers = MockHeaders::new((body.len() + 1) as u64);

        let validated_request = validate_body(headers.clone(), body.as_slice());
        assert!(validated_request.is_err());

        match validated_request {
            Ok(_) => panic!("Expected error, got success"),
            Err(error) => {
                assert_eq!(
                    error.to_string(),
                    RequestError::from(InternalRequestError::ContentLengthMismatch {
                        expected: body.len() + 1,
                        actual: body.len(),
                    })
                    .to_string()
                );
            }
        }
    }

    #[test]
    fn test_from_request() -> Result<(), Box<dyn std::error::Error>> {
        let body = ORIGINAL_PSBT.as_bytes();
        let headers = MockHeaders::new(body.len() as u64);
        let validated_request = validate_body(headers.clone(), body);
        assert!(validated_request.is_ok());

        let proposal = UncheckedProposal::from_request(body, QUERY_PARAMS, headers)?;

        let witness_utxo =
            proposal.psbt.inputs[0].witness_utxo.as_ref().expect("witness_utxo should be present");
        let address =
            Address::from_script(&witness_utxo.script_pubkey, bitcoin::params::Params::MAINNET)?;
        assert_eq!(address.address_type(), Some(AddressType::P2sh));

        assert_eq!(proposal.params.v, Version::One);
        assert_eq!(proposal.params.additional_fee_contribution, Some((Amount::from_sat(182), 0)));
        Ok(())
    }
}
