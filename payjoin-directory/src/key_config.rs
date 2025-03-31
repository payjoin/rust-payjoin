//! Manage the OHTTP key configuration

use anyhow::Result;
use tracing::info;

pub fn init_ohttp() -> Result<ohttp::Server> {
    use ohttp::hpke::{Aead, Kdf, Kem};
    use ohttp::{KeyId, SymmetricSuite};

    const KEY_ID: KeyId = 1;
    const KEM: Kem = Kem::K256Sha256;
    const SYMMETRIC: &[SymmetricSuite] =
        &[SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)];

    // create or read from file
    let server_config = ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC))?;
    info!("Initialized a new OHTTP Key Configuration. GET /ohttp-keys to fetch it.");
    Ok(ohttp::Server::new(server_config)?)
}
