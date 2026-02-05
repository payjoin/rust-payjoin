use std::path::{Path, PathBuf};
use std::time::Duration;

use config::{ConfigError, File};
use serde::Deserialize;
use tokio_listener::ListenerAddress;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub http_listener: ListenerAddress,
    pub https_listener: ListenerAddress,
    pub storage_dir: PathBuf,
    #[serde(deserialize_with = "deserialize_duration_secs")]
    pub timeout: Duration,
    #[cfg(feature = "acme")]
    pub acme: Option<AcmeConfig>,
}

#[cfg(feature = "acme")]
#[derive(Debug, Clone, Deserialize)]
pub struct AcmeConfig {
    pub domains: Vec<String>,
    pub contact: Vec<String>,
    pub cache_dir: PathBuf,
    #[serde(default)]
    pub directory_url: Option<String>,
}

#[cfg(feature = "acme")]
impl From<AcmeConfig> for tokio_rustls_acme::AcmeConfig<std::io::Error, std::io::Error> {
    fn from(acme_config: AcmeConfig) -> Self {
        let config = tokio_rustls_acme::AcmeConfig::new(acme_config.domains)
            .contact(acme_config.contact)
            .cache(tokio_rustls_acme::caches::DirCache::new(acme_config.cache_dir));
        match acme_config.directory_url {
            Some(url) => config.directory(url),
            None => config.directory_lets_encrypt(true),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            http_listener: "[::]:8080".parse().expect("valid default listener address"),
            https_listener: "[::]:4433".parse().expect("valid default listener address"),
            storage_dir: PathBuf::from("./data"),
            timeout: Duration::from_secs(30),
            #[cfg(feature = "acme")]
            acme: None,
        }
    }
}

fn deserialize_duration_secs<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let secs = u64::deserialize(deserializer)?;
    Ok(Duration::from_secs(secs))
}

impl Config {
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        config::Config::builder()
            // Add from optional config file
            .add_source(File::from(path).required(false))
            // Add from the environment (with a prefix of PJ)
            // e.g. `PJ_PORT=9090` would set the `port`.
            .add_source(config::Environment::with_prefix("PJ").separator("_"))
            .build()?
            .try_deserialize()
    }
}
