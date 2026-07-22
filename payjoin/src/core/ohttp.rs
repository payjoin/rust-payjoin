use alloc::vec;
use alloc::vec::Vec;
#[cfg(not(feature = "std"))]
use core::error;
use core::fmt;
#[cfg(not(feature = "std"))]
use core::ops::{Deref, DerefMut};
#[cfg(feature = "std")]
use std::error;

use bitcoin::bech32::{self, EncodeError};
use bitcoin::key::constants::UNCOMPRESSED_PUBLIC_KEY_SIZE;
use hpke::rand_core::{OsRng, RngCore};

use crate::directory::ENCAPSULATED_MESSAGE_BYTES;

const N_ENC: usize = UNCOMPRESSED_PUBLIC_KEY_SIZE;
const N_T: usize = crate::hpke::POLY1305_TAG_SIZE;
const OHTTP_REQ_HEADER_BYTES: usize = 7;
pub const PADDED_BHTTP_REQ_BYTES: usize =
    ENCAPSULATED_MESSAGE_BYTES - (N_ENC + N_T + OHTTP_REQ_HEADER_BYTES);

pub(crate) fn ohttp_encapsulate(
    ohttp_keys: &OhttpKeys,
    method: &str,
    target_resource: &str,
    body: Option<&[u8]>,
) -> Result<([u8; ENCAPSULATED_MESSAGE_BYTES], ohttp::ClientResponse), OhttpEncapsulationError> {
    use core::fmt::Write;
    let mut ohttp_keys = ohttp_keys.clone();

    let ctx = ohttp::ClientRequest::from_config(&mut ohttp_keys.0)?;
    let url = crate::core::Url::parse(target_resource)?;
    let authority_bytes = {
        let mut authority = url.host_str();
        if let Some(port) = url.port() {
            write!(authority, ":{port}").unwrap();
        }
        authority.into_bytes()
    };
    let mut bhttp_message = bhttp::Message::request(
        method.as_bytes().to_vec(),
        url.scheme().as_bytes().to_vec(),
        authority_bytes,
        url.path().as_bytes().to_vec(),
    );
    // None of our messages include headers, so we don't add them
    if let Some(body) = body {
        bhttp_message.write_content(body);
    }

    let mut bhttp_req = [0u8; PADDED_BHTTP_REQ_BYTES];
    OsRng.fill_bytes(&mut bhttp_req);
    bhttp_message.write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_req.as_mut_slice())?;
    let (encapsulated, ohttp_ctx) = ctx.encapsulate(&bhttp_req)?;

    let mut buffer = [0u8; ENCAPSULATED_MESSAGE_BYTES];
    let len = encapsulated.len().min(ENCAPSULATED_MESSAGE_BYTES);
    buffer[..len].copy_from_slice(&encapsulated[..len]);
    Ok((buffer, ohttp_ctx))
}

#[derive(Debug)]
pub enum DirectoryResponseError {
    InvalidSize(usize),
    OhttpDecapsulation(ohttp::Error),
    UnexpectedStatusCode(http::StatusCode),
}

impl DirectoryResponseError {
    pub(crate) fn is_fatal(&self) -> bool {
        use DirectoryResponseError::*;

        match self {
            OhttpDecapsulation(_) => true,
            InvalidSize(_) => false,
            UnexpectedStatusCode(status_code) => status_code.is_client_error(),
        }
    }
}

impl fmt::Display for DirectoryResponseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use DirectoryResponseError::*;

        match self {
            OhttpDecapsulation(e) => write!(f, "OHTTP Decapsulation Error: {e}"),
            InvalidSize(size) => write!(
                f,
                "Unexpected response size {}, expected {} bytes",
                size,
                crate::directory::ENCAPSULATED_MESSAGE_BYTES
            ),
            UnexpectedStatusCode(status) => write!(f, "Unexpected status code: {status}"),
        }
    }
}

impl error::Error for DirectoryResponseError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use DirectoryResponseError::*;

        match self {
            OhttpDecapsulation(e) => Some(e),
            InvalidSize(_) => None,
            UnexpectedStatusCode(_) => None,
        }
    }
}

#[cfg(feature = "std")]
pub(crate) fn process_get_res(
    res: &[u8],
    ohttp_context: ohttp::ClientResponse,
) -> Result<Option<Vec<u8>>, DirectoryResponseError> {
    let response = process_ohttp_res(res, ohttp_context)?;
    match response.status() {
        http::StatusCode::OK => Ok(Some(response.body().to_vec())),
        http::StatusCode::ACCEPTED => Ok(None),
        status_code => Err(DirectoryResponseError::UnexpectedStatusCode(status_code)),
    }
}

#[cfg(feature = "std")]
pub(crate) fn process_post_res(
    res: &[u8],
    ohttp_context: ohttp::ClientResponse,
) -> Result<(), DirectoryResponseError> {
    let response = process_ohttp_res(res, ohttp_context)?;
    match response.status() {
        http::StatusCode::OK => Ok(()),
        status_code => Err(DirectoryResponseError::UnexpectedStatusCode(status_code)),
    }
}

#[cfg(feature = "std")]
fn process_ohttp_res(
    res: &[u8],
    ohttp_context: ohttp::ClientResponse,
) -> Result<http::Response<Vec<u8>>, DirectoryResponseError> {
    let response_array: &[u8; crate::directory::ENCAPSULATED_MESSAGE_BYTES] =
        res.try_into().map_err(|_| DirectoryResponseError::InvalidSize(res.len()))?;
    ohttp_decapsulate(ohttp_context, response_array).map_err(|e| match e {
        OhttpEncapsulationError::Ohttp(ohttp_err) =>
            DirectoryResponseError::OhttpDecapsulation(ohttp_err),
        _ => DirectoryResponseError::InvalidSize(0),
    })
}

/// decapsulate ohttp, bhttp response and return http response body and status code
#[cfg(all(feature = "std", feature = "v2-ohttp"))]
pub(crate) fn ohttp_decapsulate(
    res_ctx: ohttp::ClientResponse,
    ohttp_body: &[u8; ENCAPSULATED_MESSAGE_BYTES],
) -> Result<http::Response<Vec<u8>>, OhttpEncapsulationError> {
    let bhttp_body = res_ctx.decapsulate(ohttp_body)?;
    let mut r = std::io::Cursor::new(bhttp_body);
    let m: bhttp::Message = bhttp::Message::read_bhttp(&mut r)?;
    let mut builder = http::Response::builder();
    for field in m.header().iter() {
        builder = builder.header(field.name(), field.value());
    }
    builder
        .status({
            let code = m.control().status().ok_or(bhttp::Error::InvalidStatus)?;

            http::StatusCode::from_u16(code.code()).map_err(|_| bhttp::Error::InvalidStatus)?
        })
        .body(m.content().to_vec())
        .map_err(OhttpEncapsulationError::Http)
}

/// Error from de/encapsulating an Oblivious HTTP request or response.
#[derive(Debug)]
pub enum OhttpEncapsulationError {
    Http(http::Error),
    Ohttp(ohttp::Error),
    Bhttp(bhttp::Error),
    ParseUrl(crate::core::UrlParseError),
}

impl From<http::Error> for OhttpEncapsulationError {
    fn from(value: http::Error) -> Self { Self::Http(value) }
}

impl From<ohttp::Error> for OhttpEncapsulationError {
    fn from(value: ohttp::Error) -> Self { Self::Ohttp(value) }
}

impl From<bhttp::Error> for OhttpEncapsulationError {
    fn from(value: bhttp::Error) -> Self { Self::Bhttp(value) }
}

impl From<crate::core::UrlParseError> for OhttpEncapsulationError {
    fn from(value: crate::core::UrlParseError) -> Self { Self::ParseUrl(value) }
}

impl fmt::Display for OhttpEncapsulationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use OhttpEncapsulationError::*;

        match &self {
            Http(e) => e.fmt(f),
            Ohttp(e) => e.fmt(f),
            Bhttp(e) => e.fmt(f),
            ParseUrl(e) => e.fmt(f),
        }
    }
}

impl error::Error for OhttpEncapsulationError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use OhttpEncapsulationError::*;

        match &self {
            Http(e) => Some(e),
            Ohttp(e) => Some(e),
            Bhttp(e) => Some(e),
            ParseUrl(e) => Some(e),
        }
    }
}

#[derive(Debug, Clone)]
pub struct OhttpKeys(ohttp::KeyConfig);

impl OhttpKeys {
    /// Decode an OHTTP KeyConfig
    pub fn decode(bytes: &[u8]) -> Result<Self, OhttpKeysError> {
        ohttp::KeyConfig::decode(bytes).map(Self).map_err(|e| OhttpKeysError::Decode(Box::new(e)))
    }

    /// Encode the OHTTP KeyConfig, decodable via [`OhttpKeys::decode`].
    pub fn encode(&self) -> Result<Vec<u8>, OhttpKeysError> {
        self.0.encode().map_err(|e| OhttpKeysError::Encode(Box::new(e)))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, OhttpKeysError> {
        let bytes = self.0.encode().map_err(|e| OhttpKeysError::Encode(Box::new(e)))?;

        let key_id = bytes[0];
        let uncompressed_pubkey = &bytes[3..68];

        let compressed_pubkey = bitcoin::secp256k1::PublicKey::from_slice(uncompressed_pubkey)
            .expect("serialization of public key should be deserializable without error")
            .serialize();

        let mut buf = vec![key_id];
        buf.extend_from_slice(&compressed_pubkey);

        Ok(buf)
    }
}

/// An opaque OHTTP client context.
///
/// Returned alongside the [`Request`](crate::Request) by a `create_*_request`
/// method and consumed by the paired `process_*` method to decapsulate the
/// directory's response. Callers hold it between the two calls without
/// inspecting it.
pub struct OhttpResponse(ohttp::ClientResponse);

impl OhttpResponse {
    pub(crate) fn new(inner: ohttp::ClientResponse) -> Self { Self(inner) }

    pub(crate) fn into_inner(self) -> ohttp::ClientResponse { self.0 }
}

const KEM_ID: &[u8] = b"\x00\x16"; // DHKEM(secp256k1, HKDF-SHA256)
const SYMMETRIC_LEN: &[u8] = b"\x00\x04"; // 4 bytes
const SYMMETRIC_KDF_AEAD: &[u8] = b"\x00\x01\x00\x03"; // KDF(HKDF-SHA256), AEAD(ChaCha20Poly1305)

impl fmt::Display for OhttpKeys {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let buf = self.to_bytes().map_err(|_| fmt::Error)?;

        let oh_hrp: bech32::Hrp =
            bech32::Hrp::parse("OH").expect("parsing a valid HRP constant should never fail");

        crate::bech32::nochecksum::encode_to_fmt(f, oh_hrp, &buf).map_err(|e| match e {
            EncodeError::Fmt(e) => e,
            _ => fmt::Error,
        })
    }
}

impl TryFrom<&[u8]> for OhttpKeys {
    type Error = OhttpKeysError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let buf: [u8; 34] =
            bytes.try_into().map_err(|_| OhttpKeysError::IncorrectLength(bytes.len()))?;

        let key_id = buf[0];
        let compressed_pk = &buf[1..];

        let pubkey = bitcoin::secp256k1::PublicKey::from_slice(compressed_pk)
            .map_err(|_| OhttpKeysError::InvalidPublicKey)?;

        let mut buf = vec![key_id];
        buf.extend_from_slice(KEM_ID);
        buf.extend_from_slice(&pubkey.serialize_uncompressed());
        buf.extend_from_slice(SYMMETRIC_LEN);
        buf.extend_from_slice(SYMMETRIC_KDF_AEAD);

        ohttp::KeyConfig::decode(&buf).map(Self).map_err(|e| OhttpKeysError::Decode(Box::new(e)))
    }
}

#[cfg(test)]
impl std::str::FromStr for OhttpKeys {
    type Err = OhttpKeysError;

    /// Parses a base64URL-encoded string into OhttpKeys.
    /// The string format is: key_id || compressed_public_key
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let oh_hrp: bech32::Hrp =
            bech32::Hrp::parse("OH").expect("parsing a valid HRP constant should never fail");

        let (hrp, bytes) =
            crate::bech32::nochecksum::decode(s).map_err(|_| OhttpKeysError::InvalidFormat)?;

        if hrp != oh_hrp {
            return Err(OhttpKeysError::InvalidFormat);
        }

        Self::try_from(&bytes[..])
    }
}

impl PartialEq for OhttpKeys {
    fn eq(&self, other: &Self) -> bool {
        match (self.0.encode(), other.0.encode()) {
            (Ok(self_encoded), Ok(other_encoded)) => self_encoded == other_encoded,
            // If the key config fails to encode, return false
            _ => false,
        }
    }
}

impl Eq for OhttpKeys {}

impl<'de> serde::Deserialize<'de> for OhttpKeys {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        OhttpKeys::decode(&bytes).map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for OhttpKeys {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.0.encode().map_err(serde::ser::Error::custom)?;
        bytes.serialize(serializer)
    }
}

/// Error encoding or decoding [`OhttpKeys`].
#[derive(Debug)]
#[non_exhaustive]
pub enum OhttpKeysError {
    /// The provided bytes were not the expected length.
    IncorrectLength(usize),
    /// The bytes did not encode a valid public key.
    InvalidPublicKey,
    /// The bytes could not be decoded as an OHTTP key config.
    Decode(Box<dyn std::error::Error + Send + Sync>),
    /// The OHTTP key config could not be encoded.
    Encode(Box<dyn std::error::Error + Send + Sync>),
    #[cfg(test)]
    InvalidFormat,
}

impl fmt::Display for OhttpKeysError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use OhttpKeysError::*;
        match self {
            IncorrectLength(l) => write!(f, "Invalid length, got {l} expected 34"),
            InvalidPublicKey => write!(f, "Invalid public key"),
            Decode(e) => write!(f, "Failed to decode OHTTP keys: {e}"),
            Encode(e) => write!(f, "Failed to encode OHTTP keys: {e}"),
            #[cfg(test)]
            InvalidFormat => write!(f, "Invalid format"),
        }
    }
}

impl error::Error for OhttpKeysError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use OhttpKeysError::*;
        match self {
            Decode(e) | Encode(e) => Some(e.as_ref()),
            IncorrectLength(_) | InvalidPublicKey => None,
            #[cfg(test)]
            InvalidFormat => None,
        }
    }
}

#[cfg(test)]
mod test {
    use payjoin_test_utils::{KEM, KEY_ID, SYMMETRIC};

    use super::*;

    #[test]
    fn test_ohttp_keys_roundtrip() {
        let keys = OhttpKeys(ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).unwrap());
        let serialized = keys.to_bytes().unwrap();
        let deserialized = OhttpKeys::try_from(&serialized[..]).unwrap();
        assert!(keys.eq(&deserialized));
    }

    #[test]
    fn test_ohttp_keys_equality() {
        use ohttp::KeyId;
        const KEY_ID_ONE: KeyId = 1;
        let keys_one =
            OhttpKeys(ohttp::KeyConfig::new(KEY_ID_ONE, KEM, Vec::from(SYMMETRIC)).unwrap());
        let serialized_one = &keys_one.to_bytes().unwrap();
        let deserialized_one = OhttpKeys::try_from(&serialized_one[..]).unwrap();

        const KEY_ID_TWO: KeyId = 2;
        let keys_two =
            OhttpKeys(ohttp::KeyConfig::new(KEY_ID_TWO, KEM, Vec::from(SYMMETRIC)).unwrap());
        let serialized_two = &keys_two.to_bytes().unwrap();
        let deserialized_two = OhttpKeys::try_from(&serialized_two[..]).unwrap();
        assert!(keys_one.eq(&deserialized_one));
        assert!(keys_two.eq(&deserialized_two));
        assert!(!keys_one.eq(&deserialized_two));
        assert!(!keys_two.eq(&deserialized_one));
    }
}
