use std::ops::{Deref, DerefMut};
use std::{error, fmt};

use bitcoin::base64::prelude::BASE64_URL_SAFE_NO_PAD;
use bitcoin::base64::Engine;
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Nonce};

pub const PADDED_MESSAGE_BYTES: usize = 7168; // 7KB

/// crypto context
///
/// <- Receiver S
/// -> Sender E, ES(payload), payload protected by knowledge of receiver key
/// <- Receiver E, EE(payload), payload protected by knowledge of sender & receiver key
#[cfg(feature = "send")]
pub fn encrypt_message_a(
    mut raw_msg: Vec<u8>,
    e_sec: SecretKey,
    s: PublicKey,
) -> Result<Vec<u8>, HpkeError> {
    let secp = Secp256k1::new();
    let e_pub = e_sec.public_key(&secp);
    let es = SharedSecret::new(&s, &e_sec);
    let cipher = ChaCha20Poly1305::new_from_slice(&es.secret_bytes())
        .map_err(|_| HpkeError::InvalidKeyLength)?;
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // key es encrypts only 1 message so 0 is unique
    let aad = &e_pub.serialize();
    let msg = pad(&mut raw_msg)?;
    let payload = Payload { msg, aad };
    let c_t: Vec<u8> = cipher.encrypt(&nonce, payload)?;
    let mut message_a = e_pub.serialize().to_vec();
    message_a.extend(&nonce[..]);
    message_a.extend(&c_t[..]);
    Ok(message_a)
}

#[cfg(feature = "receive")]
pub fn decrypt_message_a(
    message_a: &[u8],
    s: SecretKey,
) -> Result<(Vec<u8>, PublicKey), HpkeError> {
    // let message a = [pubkey/AD][nonce][authentication tag][ciphertext]
    let e = PublicKey::from_slice(message_a.get(..33).ok_or(HpkeError::PayloadTooShort)?)?;
    let nonce = Nonce::from_slice(message_a.get(33..45).ok_or(HpkeError::PayloadTooShort)?);
    let es = SharedSecret::new(&e, &s);
    let cipher = ChaCha20Poly1305::new_from_slice(&es.secret_bytes())
        .map_err(|_| HpkeError::InvalidKeyLength)?;
    let c_t = message_a.get(45..).ok_or(HpkeError::PayloadTooShort)?;
    let aad = &e.serialize();
    let payload = Payload { msg: c_t, aad };
    let buffer = cipher.decrypt(nonce, payload)?;
    Ok((buffer, e))
}

#[cfg(feature = "receive")]
pub fn encrypt_message_b(raw_msg: &mut Vec<u8>, re_pub: PublicKey) -> Result<Vec<u8>, HpkeError> {
    // let message b = [pubkey/AD][nonce][authentication tag][ciphertext]
    let secp = Secp256k1::new();
    let (e_sec, e_pub) = secp.generate_keypair(&mut OsRng);
    let ee = SharedSecret::new(&re_pub, &e_sec);
    let cipher = ChaCha20Poly1305::new_from_slice(&ee.secret_bytes())
        .map_err(|_| HpkeError::InvalidKeyLength)?;
    let nonce = Nonce::from_slice(&[0u8; 12]); // key es encrypts only 1 message so 0 is unique
    let aad = &e_pub.serialize();
    let msg = pad(raw_msg)?;
    let payload = Payload { msg, aad };
    let c_t = cipher.encrypt(nonce, payload)?;
    let mut message_b = e_pub.serialize().to_vec();
    message_b.extend(&nonce[..]);
    message_b.extend(&c_t[..]);
    Ok(message_b)
}

#[cfg(feature = "send")]
pub fn decrypt_message_b(message_b: &mut [u8], e: SecretKey) -> Result<Vec<u8>, HpkeError> {
    // let message b = [pubkey/AD][nonce][authentication tag][ciphertext]
    let re = PublicKey::from_slice(message_b.get(..33).ok_or(HpkeError::PayloadTooShort)?)?;
    let nonce = Nonce::from_slice(message_b.get(33..45).ok_or(HpkeError::PayloadTooShort)?);
    let ee = SharedSecret::new(&re, &e);
    let cipher = ChaCha20Poly1305::new_from_slice(&ee.secret_bytes())
        .map_err(|_| HpkeError::InvalidKeyLength)?;
    let payload = Payload {
        msg: message_b.get(45..).ok_or(HpkeError::PayloadTooShort)?,
        aad: &re.serialize(),
    };
    let buffer = cipher.decrypt(nonce, payload)?;
    Ok(buffer)
}

fn pad(msg: &mut Vec<u8>) -> Result<&[u8], HpkeError> {
    if msg.len() > PADDED_MESSAGE_BYTES {
        return Err(HpkeError::PayloadTooLarge);
    }
    while msg.len() < PADDED_MESSAGE_BYTES {
        msg.push(0);
    }
    Ok(msg)
}

/// Error from de/encrypting a v2 Hybrid Public Key Encryption payload.
#[derive(Debug)]
pub enum HpkeError {
    Secp256k1(bitcoin::secp256k1::Error),
    ChaCha20Poly1305(chacha20poly1305::aead::Error),
    InvalidKeyLength,
    PayloadTooLarge,
    PayloadTooShort,
}

impl From<bitcoin::secp256k1::Error> for HpkeError {
    fn from(value: bitcoin::secp256k1::Error) -> Self { Self::Secp256k1(value) }
}

impl From<chacha20poly1305::aead::Error> for HpkeError {
    fn from(value: chacha20poly1305::aead::Error) -> Self { Self::ChaCha20Poly1305(value) }
}

impl fmt::Display for HpkeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use HpkeError::*;

        match &self {
            Secp256k1(e) => e.fmt(f),
            ChaCha20Poly1305(e) => e.fmt(f),
            InvalidKeyLength => write!(f, "Invalid Length"),
            PayloadTooLarge =>
                write!(f, "Payload too large, max size is {} bytes", PADDED_MESSAGE_BYTES),
            PayloadTooShort => write!(f, "Payload too small"),
        }
    }
}

impl error::Error for HpkeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use HpkeError::*;

        match &self {
            Secp256k1(e) => Some(e),
            ChaCha20Poly1305(_) | InvalidKeyLength | PayloadTooLarge | PayloadTooShort => None,
        }
    }
}

pub fn ohttp_encapsulate(
    ohttp_keys: &mut ohttp::KeyConfig,
    method: &str,
    target_resource: &str,
    body: Option<&[u8]>,
) -> Result<(Vec<u8>, ohttp::ClientResponse), OhttpEncapsulationError> {
    use std::fmt::Write;

    let ctx = ohttp::ClientRequest::from_config(ohttp_keys)?;
    let url = url::Url::parse(target_resource)?;
    let authority_bytes = url.host().map_or_else(Vec::new, |host| {
        let mut authority = host.to_string();
        if let Some(port) = url.port() {
            write!(authority, ":{}", port).unwrap();
        }
        authority.into_bytes()
    });
    let mut bhttp_message = bhttp::Message::request(
        method.as_bytes().to_vec(),
        url.scheme().as_bytes().to_vec(),
        authority_bytes,
        url.path().as_bytes().to_vec(),
    );
    if let Some(body) = body {
        bhttp_message.write_content(body);
    }
    let mut bhttp_req = Vec::new();
    let _ = bhttp_message.write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_req);
    let encapsulated = ctx.encapsulate(&bhttp_req)?;
    Ok(encapsulated)
}

/// decapsulate ohttp, bhttp response and return http response body and status code
pub fn ohttp_decapsulate(
    res_ctx: ohttp::ClientResponse,
    ohttp_body: &[u8],
) -> Result<http::Response<Vec<u8>>, OhttpEncapsulationError> {
    let bhttp_body = res_ctx.decapsulate(ohttp_body)?;
    let mut r = std::io::Cursor::new(bhttp_body);
    let m: bhttp::Message = bhttp::Message::read_bhttp(&mut r)?;
    http::Response::builder()
        .status(m.control().status().unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR.into()))
        .body(m.content().to_vec())
        .map_err(OhttpEncapsulationError::Http)
}

/// Error from de/encapsulating an Oblivious HTTP request or response.
#[derive(Debug)]
pub enum OhttpEncapsulationError {
    Http(http::Error),
    Ohttp(ohttp::Error),
    Bhttp(bhttp::Error),
    ParseUrl(url::ParseError),
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

impl From<url::ParseError> for OhttpEncapsulationError {
    fn from(value: url::ParseError) -> Self { Self::ParseUrl(value) }
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
pub struct OhttpKeys(pub ohttp::KeyConfig);

impl OhttpKeys {
    /// Decode an OHTTP KeyConfig
    pub fn decode(bytes: &[u8]) -> Result<Self, ohttp::Error> {
        ohttp::KeyConfig::decode(bytes).map(Self)
    }
}

impl fmt::Display for OhttpKeys {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let encoded = BASE64_URL_SAFE_NO_PAD.encode(self.encode().map_err(|_| fmt::Error)?);
        write!(f, "{}", encoded)
    }
}

impl std::str::FromStr for OhttpKeys {
    type Err = ParseOhttpKeysError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = BASE64_URL_SAFE_NO_PAD.decode(s).map_err(ParseOhttpKeysError::DecodeBase64)?;
        OhttpKeys::decode(&bytes).map_err(ParseOhttpKeysError::DecodeKeyConfig)
    }
}

impl PartialEq for OhttpKeys {
    fn eq(&self, other: &Self) -> bool {
        match (self.encode(), other.encode()) {
            (Ok(self_encoded), Ok(other_encoded)) => self_encoded == other_encoded,
            // If OhttpKeys::encode(&self) is Err, return false
            _ => false,
        }
    }
}

impl Eq for OhttpKeys {}

impl Deref for OhttpKeys {
    type Target = ohttp::KeyConfig;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl DerefMut for OhttpKeys {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.0 }
}

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
        let bytes = self.encode().map_err(serde::ser::Error::custom)?;
        bytes.serialize(serializer)
    }
}

#[derive(Debug)]
pub enum ParseOhttpKeysError {
    DecodeBase64(bitcoin::base64::DecodeError),
    DecodeKeyConfig(ohttp::Error),
}

impl std::fmt::Display for ParseOhttpKeysError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseOhttpKeysError::DecodeBase64(e) => write!(f, "Failed to decode base64: {}", e),
            ParseOhttpKeysError::DecodeKeyConfig(e) =>
                write!(f, "Failed to decode KeyConfig: {}", e),
        }
    }
}

impl std::error::Error for ParseOhttpKeysError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseOhttpKeysError::DecodeBase64(e) => Some(e),
            ParseOhttpKeysError::DecodeKeyConfig(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_ohttp_keys_roundtrip() {
        use std::str::FromStr;

        use ohttp::hpke::{Aead, Kdf, Kem};
        use ohttp::{KeyId, SymmetricSuite};
        const KEY_ID: KeyId = 1;
        const KEM: Kem = Kem::X25519Sha256;
        const SYMMETRIC: &[SymmetricSuite] =
            &[ohttp::SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)];
        let keys = OhttpKeys(ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).unwrap());
        let serialized = &keys.to_string();
        let deserialized = OhttpKeys::from_str(serialized).unwrap();
        assert_eq!(keys.encode().unwrap(), deserialized.encode().unwrap());
    }
}
