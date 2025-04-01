//! Manage the OHTTP key configuration

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use ohttp::hpke::{Aead, Kdf, Kem};
use ohttp::SymmetricSuite;
use tracing::info;

const KEY_ID: u8 = 1;
const KEM: Kem = Kem::K256Sha256;
const SYMMETRIC: &[SymmetricSuite] =
    &[SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)];

/// OHTTP server key configuration
///
/// This is combined so that the test path and the prod path both use the same
/// code. The ServerKeyConfig.ikm is persisted to the configured path, and the
/// server is used to run the directory server.
#[derive(Debug, Clone)]
pub struct ServerKeyConfig {
    ikm: [u8; 32],
    server: ohttp::Server,
}

impl From<ServerKeyConfig> for ohttp::Server {
    fn from(value: ServerKeyConfig) -> Self { value.server }
}

/// Generate a new OHTTP server key configuration
pub fn gen_ohttp_server_config() -> Result<ServerKeyConfig> {
    let ikm = bitcoin::key::rand::random::<[u8; 32]>();
    let config = ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC))?;
    Ok(ServerKeyConfig { ikm, server: ohttp::Server::new(config)? })
}

/// Persist an OHTTP Key Configuration to the default path
pub fn persist_new_key_config(ohttp_config: ServerKeyConfig, dir: &Path) -> Result<PathBuf> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let key_path = key_path(dir);

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&key_path)
        .map_err(|e| anyhow!("Failed to create new OHTTP key file: {}", e))?;

    file.write_all(&ohttp_config.ikm)
        .map_err(|e| anyhow!("Failed to write OHTTP keys to file: {}", e))?;
    info!("Saved OHTTP Key Configuration to {}", &key_path.display());

    Ok(key_path)
}

/// Read the configured server from the default path
/// May panic if key exists but is the unexpected format.
pub fn read_server_config(dir: &Path) -> Result<ServerKeyConfig> {
    let key_path = key_path(dir);
    let ikm: [u8; 32] = fs::read(&key_path)
        .map_err(|e| anyhow!("Failed to read OHTTP key file: {}", e))?
        .try_into()
        .expect("Key wrong size: expected 32 bytes");

    let server_config = ohttp::KeyConfig::derive(KEY_ID, KEM, SYMMETRIC.to_vec(), &ikm)
        .expect("Failed to derive OHTTP keys from file");

    info!("Loaded existing OHTTP Key Configuration from {}", key_path.display());
    Ok(ServerKeyConfig { ikm, server: ohttp::Server::new(server_config)? })
}

/// Get the path to the key configuration file
/// For now, default to [KEY_ID].ikm.
/// In the future this might be able to save multiple keys named by KeyId.
fn key_path(dir: &Path) -> PathBuf { dir.join(format!("{}.ikm", KEY_ID)) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_server_config() {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let ohttp_config = gen_ohttp_server_config().expect("Failed to generate server config");
        let _path = persist_new_key_config(ohttp_config.clone(), temp_dir.path())
            .expect("Failed to persist server config");
        let ohttp_config_again =
            read_server_config(temp_dir.path()).expect("Failed to read server config");
        assert_eq!(ohttp_config.ikm, ohttp_config_again.ikm);
    }
}
