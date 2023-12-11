use std::{error, fmt};

pub const MAX_BUFFER_SIZE: usize = 65536;
pub const PADDED_MESSAGE_BYTES: usize = 7168; // 7KB

pub fn subdir(path: &str) -> String {
    let subdirectory: String;

    if let Some(pos) = path.rfind('/') {
        subdirectory = path[pos + 1..].to_string();
    } else {
        subdirectory = path.to_string();
    }

    let pubkey_id: String;

    if let Some(pos) = subdirectory.find('?') {
        pubkey_id = subdirectory[..pos].to_string();
    } else {
        pubkey_id = subdirectory;
    }
    pubkey_id
}

use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Nonce};

/// crypto context
///
/// <- Receiver S
/// -> Sender E, ES(payload), payload protected by knowledge of receiver key
/// <- Receiver E, EE(payload), payload protected by knowledge of sender & receiver key
pub fn encrypt_message_a(
    mut raw_msg: Vec<u8>,
    s: PublicKey,
) -> Result<(Vec<u8>, SecretKey), Error> {
    let secp = Secp256k1::new();
    let (e_sec, e_pub) = secp.generate_keypair(&mut OsRng);
    let es = SharedSecret::new(&s, &e_sec);
    let cipher = ChaCha20Poly1305::new_from_slice(&es.secret_bytes())
        .map_err(|_| InternalError::InvalidKeyLength)?;
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // key es encrypts only 1 message so 0 is unique
    let aad = &e_pub.serialize();
    let msg = pad(&mut raw_msg)?;
    let payload = Payload { msg, aad };
    let c_t: Vec<u8> = cipher.encrypt(&nonce, payload)?;
    let mut message_a = e_pub.serialize().to_vec();
    message_a.extend(&nonce[..]);
    message_a.extend(&c_t[..]);
    Ok((message_a, e_sec))
}

pub fn decrypt_message_a(message_a: &[u8], s: SecretKey) -> Result<(Vec<u8>, PublicKey), Error> {
    // let message a = [pubkey/AD][nonce][authentication tag][ciphertext]
    let e = PublicKey::from_slice(&message_a[..33])?;
    let nonce = Nonce::from_slice(&message_a[33..45]);
    let es = SharedSecret::new(&e, &s);
    let cipher = ChaCha20Poly1305::new_from_slice(&es.secret_bytes())
        .map_err(|_| InternalError::InvalidKeyLength)?;
    let c_t = &message_a[45..];
    let aad = &e.serialize();
    let payload = Payload { msg: c_t, aad };
    let buffer = cipher.decrypt(nonce, payload)?;
    Ok((buffer, e))
}

pub fn encrypt_message_b(raw_msg: &mut Vec<u8>, re_pub: PublicKey) -> Result<Vec<u8>, Error> {
    // let message b = [pubkey/AD][nonce][authentication tag][ciphertext]
    let secp = Secp256k1::new();
    let (e_sec, e_pub) = secp.generate_keypair(&mut OsRng);
    let ee = SharedSecret::new(&re_pub, &e_sec);
    let cipher = ChaCha20Poly1305::new_from_slice(&ee.secret_bytes())
        .map_err(|_| InternalError::InvalidKeyLength)?;
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

pub fn decrypt_message_b(message_b: &mut [u8], e: SecretKey) -> Result<Vec<u8>, Error> {
    // let message b = [pubkey/AD][nonce][authentication tag][ciphertext]
    let re = PublicKey::from_slice(&message_b[..33])?;
    let nonce = Nonce::from_slice(&message_b[33..45]);
    let ee = SharedSecret::new(&re, &e);
    let cipher = ChaCha20Poly1305::new_from_slice(&ee.secret_bytes())
        .map_err(|_| InternalError::InvalidKeyLength)?;
    let payload = Payload { msg: &message_b[45..], aad: &re.serialize() };
    let buffer = cipher.decrypt(nonce, payload)?;
    Ok(buffer)
}

fn pad(msg: &mut Vec<u8>) -> Result<&[u8], Error> {
    if msg.len() > PADDED_MESSAGE_BYTES {
        return Err(Error(InternalError::PayloadTooLarge));
    }
    while msg.len() < PADDED_MESSAGE_BYTES {
        msg.push(0);
    }
    Ok(msg)
}

/// Error that may occur when de/encrypting or de/capsulating a v2 message.
///
/// This is currently opaque type because we aren't sure which variants will stay.
/// You can only display it.
#[derive(Debug)]
pub struct Error(InternalError);

#[derive(Debug)]
pub(crate) enum InternalError {
    Ohttp(ohttp::Error),
    Bhttp(bhttp::Error),
    ParseUrl(url::ParseError),
    Secp256k1(bitcoin::secp256k1::Error),
    ChaCha20Poly1305(chacha20poly1305::aead::Error),
    InvalidKeyLength,
    PayloadTooLarge,
}

impl From<ohttp::Error> for Error {
    fn from(value: ohttp::Error) -> Self { Self(InternalError::Ohttp(value)) }
}

impl From<bhttp::Error> for Error {
    fn from(value: bhttp::Error) -> Self { Self(InternalError::Bhttp(value)) }
}

impl From<url::ParseError> for Error {
    fn from(value: url::ParseError) -> Self { Self(InternalError::ParseUrl(value)) }
}

impl From<bitcoin::secp256k1::Error> for Error {
    fn from(value: bitcoin::secp256k1::Error) -> Self { Self(InternalError::Secp256k1(value)) }
}

impl From<chacha20poly1305::aead::Error> for Error {
    fn from(value: chacha20poly1305::aead::Error) -> Self {
        Self(InternalError::ChaCha20Poly1305(value))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use InternalError::*;

        match &self.0 {
            Ohttp(e) => e.fmt(f),
            Bhttp(e) => e.fmt(f),
            ParseUrl(e) => e.fmt(f),
            Secp256k1(e) => e.fmt(f),
            ChaCha20Poly1305(e) => e.fmt(f),
            InvalidKeyLength => write!(f, "Invalid Length"),
            PayloadTooLarge =>
                write!(f, "Payload too large, max size is {} bytes", PADDED_MESSAGE_BYTES),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use InternalError::*;

        match &self.0 {
            Ohttp(e) => Some(e),
            Bhttp(e) => Some(e),
            ParseUrl(e) => Some(e),
            Secp256k1(e) => Some(e),
            ChaCha20Poly1305(_) | InvalidKeyLength | PayloadTooLarge => None,
        }
    }
}

impl From<InternalError> for Error {
    fn from(value: InternalError) -> Self { Self(value) }
}

pub fn ohttp_encapsulate(
    ohttp_config: &[u8],
    method: &str,
    target_resource: &str,
    body: Option<&[u8]>,
) -> Result<(Vec<u8>, ohttp::ClientResponse), Error> {
    let ctx = ohttp::ClientRequest::from_encoded_config(ohttp_config)?;
    let url = url::Url::parse(target_resource)?;
    let mut bhttp_message = bhttp::Message::request(
        method.as_bytes().to_vec(),
        url.scheme().as_bytes().to_vec(),
        url.authority().as_bytes().to_vec(),
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
) -> Result<Vec<u8>, Error> {
    let bhttp_body = res_ctx.decapsulate(ohttp_body)?;
    let mut r = std::io::Cursor::new(bhttp_body);
    let response = bhttp::Message::read_bhttp(&mut r)?;
    Ok(response.content().to_vec())
}
