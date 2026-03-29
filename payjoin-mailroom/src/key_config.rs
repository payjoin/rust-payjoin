//! Manage the OHTTP key configuration

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Result};
use ohttp::hpke::{Aead, Kdf, Kem};
use ohttp::SymmetricSuite;
use tracing::info;

const DEFAULT_KEY_ID: u8 = 0;
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
    key_id: u8,
    ikm: [u8; 32],
    server: ohttp::Server,
}

impl ServerKeyConfig {
    pub fn key_id(&self) -> u8 { self.key_id }

    pub fn into_server(self) -> ohttp::Server { self.server }
}

impl From<ServerKeyConfig> for ohttp::Server {
    fn from(value: ServerKeyConfig) -> Self { value.server }
}

/// Generate a new OHTTP server key configuration with the default key ID.
pub fn gen_ohttp_server_config() -> Result<ServerKeyConfig> {
    gen_ohttp_server_config_with_id(DEFAULT_KEY_ID)
}

/// Generate a new OHTTP server key configuration with a specific key ID.
pub fn gen_ohttp_server_config_with_id(key_id: u8) -> Result<ServerKeyConfig> {
    let ikm = bitcoin::key::rand::random::<[u8; 32]>();
    let config = ohttp::KeyConfig::new(key_id, KEM, Vec::from(SYMMETRIC))?;
    Ok(ServerKeyConfig { key_id, ikm, server: ohttp::Server::new(config)? })
}

/// Persist an OHTTP Key Configuration to the directory, named by its key_id.
pub async fn persist_key_config(ohttp_config: &ServerKeyConfig, dir: &Path) -> Result<PathBuf> {
    use tokio::fs::OpenOptions;
    use tokio::io::AsyncWriteExt;

    let key_path = key_path_for_id(dir, ohttp_config.key_id);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&key_path)
        .await
        .map_err(|e| anyhow!("Failed to create OHTTP key file: {}", e))?;

    file.write_all(&ohttp_config.ikm)
        .await
        .map_err(|e| anyhow!("Failed to write OHTTP keys to file: {}", e))?;
    file.flush().await.map_err(|e| anyhow!("Failed to flush OHTTP key file: {}", e))?;
    info!(
        "Saved OHTTP Key Configuration (key_id={}) to {}",
        ohttp_config.key_id,
        key_path.display()
    );
    Ok(key_path)
}

/// Read a single server config for a specific key_id from the directory.
///  May  panic if key exists but is the unexpected format.
pub fn read_server_config_for_id(dir: &Path, key_id: u8) -> Result<ServerKeyConfig> {
    let key_path = key_path_for_id(dir, key_id);
    let ikm: [u8; 32] = fs::read(&key_path)
        .map_err(|e| anyhow!("Failed to read OHTTP key file: {}", e))?
        .try_into()
        .expect("Key wrong size: expected 32 bytes");

    let server_config = ohttp::KeyConfig::derive(key_id, KEM, SYMMETRIC.to_vec(), &ikm)
        .expect("Failed to derive OHTTP keys from file");

    info!("Loaded OHTTP Key Configuration (key_id={key_id}) from {}", key_path.display());
    Ok(ServerKeyConfig { key_id, ikm, server: ohttp::Server::new(server_config)? })
}

/// Read the legacy single-key config (key_id=0).
pub fn read_server_config(dir: &Path) -> Result<ServerKeyConfig> {
    read_server_config_for_id(dir, DEFAULT_KEY_ID)
}

pub(crate) fn key_path_for_id(dir: &Path, key_id: u8) -> PathBuf {
    dir.join(format!("{key_id}.ikm"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip_server_config() {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let ohttp_config = gen_ohttp_server_config().expect("Failed to generate server config");
        let _path = persist_key_config(&ohttp_config, temp_dir.path())
            .await
            .expect("Failed to persist server config");
        let ohttp_config_again =
            read_server_config(temp_dir.path()).expect("Failed to read server config");
        assert_eq!(ohttp_config.ikm, ohttp_config_again.ikm);
        assert_eq!(ohttp_config.key_id, ohttp_config_again.key_id);
    }

    #[tokio::test]
    async fn round_trip_with_custom_key_id() {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let config = gen_ohttp_server_config_with_id(42).expect("gen config");
        assert_eq!(config.key_id(), 42);
        persist_key_config(&config, temp_dir.path()).await.expect("persist");
        let loaded = read_server_config_for_id(temp_dir.path(), 42).expect("read");
        assert_eq!(config.ikm, loaded.ikm);
        assert_eq!(loaded.key_id(), 42);
    }

    #[tokio::test]
    async fn read_both_configs() {
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        let c0 = gen_ohttp_server_config_with_id(0).expect("gen");
        let c1 = gen_ohttp_server_config_with_id(1).expect("gen");
        persist_key_config(&c0, temp_dir.path()).await.expect("persist");
        persist_key_config(&c1, temp_dir.path()).await.expect("persist");

        let loaded0 = read_server_config_for_id(temp_dir.path(), 0).expect("read 0");
        let loaded1 = read_server_config_for_id(temp_dir.path(), 1).expect("read 1");
        assert_eq!(c0.ikm, loaded0.ikm);
        assert_eq!(c1.ikm, loaded1.ikm);
    }

    fn parse_key_id_from_path(path: &Path) -> Option<u8> {
        let name = path.file_name()?.to_str()?;
        let stem = name.strip_suffix(".ikm")?;
        stem.parse::<u8>().ok()
    }

    #[test]
    fn parse_key_id_from_filename() {
        assert_eq!(parse_key_id_from_path(Path::new("1.ikm")), Some(1));
        assert_eq!(parse_key_id_from_path(Path::new("255.ikm")), Some(255));
        assert_eq!(parse_key_id_from_path(Path::new("foo.ikm")), None);
        assert_eq!(parse_key_id_from_path(Path::new("1.txt")), None);
        assert_eq!(parse_key_id_from_path(Path::new("256.ikm")), None);
    }
}
