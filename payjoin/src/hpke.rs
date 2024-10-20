use std::ops::Deref;
use std::{error, fmt};

use bitcoin::key::constants::{ELLSWIFT_ENCODING_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE};
use bitcoin::secp256k1::ellswift::ElligatorSwift;
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::SecpK256HkdfSha256;
use hpke::rand_core::OsRng;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Serialize};

pub const PADDED_MESSAGE_BYTES: usize = 7168;
pub const PADDED_PLAINTEXT_A_LENGTH: usize = PADDED_MESSAGE_BYTES - ELLSWIFT_ENCODING_SIZE;
pub const PADDED_PLAINTEXT_B_LENGTH: usize = PADDED_MESSAGE_BYTES - UNCOMPRESSED_PUBLIC_KEY_SIZE;
pub const INFO_A: &[u8; 8] = b"PjV2MsgA";
pub const INFO_B: &[u8; 8] = b"PjV2MsgB";

pub type SecretKey = <SecpK256HkdfSha256 as hpke::Kem>::PrivateKey;
pub type PublicKey = <SecpK256HkdfSha256 as hpke::Kem>::PublicKey;
pub type EncappedKey = <SecpK256HkdfSha256 as hpke::Kem>::EncappedKey;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HpkeKeyPair(pub HpkeSecretKey, pub HpkePublicKey);

impl From<HpkeKeyPair> for (HpkeSecretKey, HpkePublicKey) {
    fn from(value: HpkeKeyPair) -> Self { (value.0, value.1) }
}

impl HpkeKeyPair {
    pub fn gen_keypair() -> Self {
        let (sk, pk) = <SecpK256HkdfSha256 as hpke::Kem>::gen_keypair(&mut OsRng);
        Self(HpkeSecretKey(sk), HpkePublicKey(pk))
    }
    pub fn secret_key(&self) -> &HpkeSecretKey { &self.0 }
    pub fn public_key(&self) -> &HpkePublicKey { &self.1 }
}

fn encapped_key_from_ellswift_bytes(encoded: &[u8]) -> Result<EncappedKey, HpkeError> {
    let mut buf = [0u8; ELLSWIFT_ENCODING_SIZE];
    buf.copy_from_slice(encoded);
    let ellswift = ElligatorSwift::from_array(buf);
    let pk = bitcoin::secp256k1::PublicKey::from_ellswift(ellswift);
    Ok(EncappedKey::from_bytes(pk.serialize_uncompressed().as_slice())?)
}

fn ellswift_bytes_from_encapped_key(
    enc: &EncappedKey,
) -> Result<[u8; ELLSWIFT_ENCODING_SIZE], HpkeError> {
    let uncompressed = enc.to_bytes();
    let pk = bitcoin::secp256k1::PublicKey::from_slice(&uncompressed)?;
    let ellswift = ElligatorSwift::from_pubkey(pk);
    Ok(ellswift.to_array())
}

#[derive(Clone, PartialEq, Eq)]
pub struct HpkeSecretKey(pub SecretKey);

impl Deref for HpkeSecretKey {
    type Target = SecretKey;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl core::fmt::Debug for HpkeSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecpHpkeSecretKey([REDACTED])")
    }
}

impl serde::Serialize for HpkeSecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_bytes())
    }
}

impl<'de> serde::Deserialize<'de> for HpkeSecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(HpkeSecretKey(
            SecretKey::from_bytes(&bytes)
                .map_err(|_| serde::de::Error::custom("Invalid secret key"))?,
        ))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct HpkePublicKey(pub PublicKey);

impl HpkePublicKey {
    pub fn to_compressed_bytes(&self) -> [u8; 33] {
        let compressed_key = bitcoin::secp256k1::PublicKey::from_slice(&self.0.to_bytes())
            .expect("Invalid public key from known valid bytes");
        compressed_key.serialize()
    }

    pub fn from_compressed_bytes(bytes: &[u8]) -> Result<Self, HpkeError> {
        let compressed_key = bitcoin::secp256k1::PublicKey::from_slice(bytes)?;
        Ok(HpkePublicKey(PublicKey::from_bytes(
            compressed_key.serialize_uncompressed().as_slice(),
        )?))
    }
}

impl Deref for HpkePublicKey {
    type Target = PublicKey;

    fn deref(&self) -> &Self::Target { &self.0 }
}

impl core::fmt::Debug for HpkePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecpHpkePublicKey({:?})", self.0)
    }
}

impl serde::Serialize for HpkePublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0.to_bytes())
    }
}

impl<'de> serde::Deserialize<'de> for HpkePublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        Ok(HpkePublicKey(
            PublicKey::from_bytes(&bytes)
                .map_err(|_| serde::de::Error::custom("Invalid public key"))?,
        ))
    }
}

/// Message A is sent from the sender to the receiver containing an Original PSBT payload
#[cfg(feature = "send")]
pub fn encrypt_message_a(
    body: Vec<u8>,
    reply_pk: &HpkePublicKey,
    receiver_pk: &HpkePublicKey,
) -> Result<Vec<u8>, HpkeError> {
    let (encapsulated_key, mut encryption_context) =
        hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, SecpK256HkdfSha256, _>(
            &OpModeS::Base,
            &receiver_pk.0,
            INFO_A,
            &mut OsRng,
        )?;
    let mut plaintext = reply_pk.to_bytes().to_vec();
    plaintext.extend(body);
    let plaintext = pad_plaintext(&mut plaintext, PADDED_PLAINTEXT_A_LENGTH)?;
    let ciphertext = encryption_context.seal(plaintext, &[])?;
    let mut message_a = ellswift_bytes_from_encapped_key(&encapsulated_key)?.to_vec();
    message_a.extend(&ciphertext);
    Ok(message_a.to_vec())
}

#[cfg(feature = "receive")]
pub fn decrypt_message_a(
    message_a: &[u8],
    receiver_sk: HpkeSecretKey,
) -> Result<(Vec<u8>, HpkePublicKey), HpkeError> {
    use std::io::{Cursor, Read};

    let mut cursor = Cursor::new(message_a);

    let mut enc_bytes = [0u8; ELLSWIFT_ENCODING_SIZE];
    cursor.read_exact(&mut enc_bytes).map_err(|_| HpkeError::PayloadTooShort)?;
    let enc = encapped_key_from_ellswift_bytes(&enc_bytes)?;

    let mut decryption_ctx = hpke::setup_receiver::<
        ChaCha20Poly1305,
        HkdfSha256,
        SecpK256HkdfSha256,
    >(&OpModeR::Base, &receiver_sk.0, &enc, INFO_A)?;

    let mut ciphertext = Vec::new();
    cursor.read_to_end(&mut ciphertext).map_err(|_| HpkeError::PayloadTooShort)?;
    let plaintext = decryption_ctx.open(&ciphertext, &[])?;

    let reply_pk_bytes = &plaintext[..UNCOMPRESSED_PUBLIC_KEY_SIZE];
    let reply_pk = HpkePublicKey(PublicKey::from_bytes(reply_pk_bytes)?);

    let body = &plaintext[UNCOMPRESSED_PUBLIC_KEY_SIZE..];

    Ok((body.to_vec(), reply_pk))
}

/// Message B is sent from the receiver to the sender containing a Payjoin PSBT payload or an error
#[cfg(feature = "receive")]
pub fn encrypt_message_b(
    mut plaintext: Vec<u8>,
    receiver_keypair: &HpkeKeyPair,
    sender_pk: &HpkePublicKey,
) -> Result<Vec<u8>, HpkeError> {
    let (encapsulated_key, mut encryption_context) =
        hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, SecpK256HkdfSha256, _>(
            &OpModeS::Auth((
                receiver_keypair.secret_key().0.clone(),
                receiver_keypair.public_key().0.clone(),
            )),
            &sender_pk.0,
            INFO_B,
            &mut OsRng,
        )?;
    let plaintext: &[u8] = pad_plaintext(&mut plaintext, PADDED_PLAINTEXT_B_LENGTH)?;
    let ciphertext = encryption_context.seal(plaintext, &[])?;
    let mut message_b = ellswift_bytes_from_encapped_key(&encapsulated_key)?.to_vec();
    message_b.extend(&ciphertext);
    Ok(message_b.to_vec())
}

#[cfg(feature = "send")]
pub fn decrypt_message_b(
    message_b: &[u8],
    receiver_pk: HpkePublicKey,
    sender_sk: HpkeSecretKey,
) -> Result<Vec<u8>, HpkeError> {
    let enc = message_b.get(..ELLSWIFT_ENCODING_SIZE).ok_or(HpkeError::PayloadTooShort)?;
    let enc = encapped_key_from_ellswift_bytes(enc)?;
    let mut decryption_ctx = hpke::setup_receiver::<
        ChaCha20Poly1305,
        HkdfSha256,
        SecpK256HkdfSha256,
    >(&OpModeR::Auth(receiver_pk.0), &sender_sk.0, &enc, INFO_B)?;
    let plaintext = decryption_ctx
        .open(message_b.get(ELLSWIFT_ENCODING_SIZE..).ok_or(HpkeError::PayloadTooShort)?, &[])?;
    Ok(plaintext)
}

fn pad_plaintext(msg: &mut Vec<u8>, padded_length: usize) -> Result<&[u8], HpkeError> {
    if msg.len() > padded_length {
        return Err(HpkeError::PayloadTooLarge { actual: msg.len(), max: padded_length });
    }
    msg.resize(padded_length, 0);
    Ok(msg)
}

/// Error from de/encrypting a v2 Hybrid Public Key Encryption payload.
#[derive(Debug)]
pub enum HpkeError {
    Secp256k1(bitcoin::secp256k1::Error),
    Hpke(hpke::HpkeError),
    InvalidKeyLength,
    PayloadTooLarge { actual: usize, max: usize },
    PayloadTooShort,
}

impl From<hpke::HpkeError> for HpkeError {
    fn from(value: hpke::HpkeError) -> Self { Self::Hpke(value) }
}

impl From<bitcoin::secp256k1::Error> for HpkeError {
    fn from(value: bitcoin::secp256k1::Error) -> Self { Self::Secp256k1(value) }
}

impl fmt::Display for HpkeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use HpkeError::*;

        match &self {
            Hpke(e) => e.fmt(f),
            InvalidKeyLength => write!(f, "Invalid Length"),
            PayloadTooLarge { actual, max } => {
                write!(
                    f,
                    "Plaintext too large, max size is {} bytes, actual size is {} bytes",
                    max, actual
                )
            }
            PayloadTooShort => write!(f, "Payload too small"),
            Secp256k1(e) => e.fmt(f),
        }
    }
}

impl error::Error for HpkeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use HpkeError::*;

        match &self {
            Hpke(e) => Some(e),
            PayloadTooLarge { .. } => None,
            InvalidKeyLength | PayloadTooShort => None,
            Secp256k1(e) => Some(e),
        }
    }
}
