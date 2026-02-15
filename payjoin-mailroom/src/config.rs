use std::path::{Path, PathBuf};
use std::time::Duration;

use config::{ConfigError, File};
use serde::Deserialize;
use tokio_listener::ListenerAddress;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub listener: ListenerAddress,
    pub storage_dir: PathBuf,
    #[serde(deserialize_with = "deserialize_duration_secs")]
    pub timeout: Duration,
    #[cfg(feature = "telemetry")]
    pub telemetry: Option<TelemetryConfig>,
    #[cfg(feature = "acme")]
    pub acme: Option<AcmeConfig>,
    #[cfg(feature = "access-control")]
    pub access_control: Option<AccessControlConfig>,
}

#[cfg(feature = "telemetry")]
#[derive(Debug, Clone, Deserialize)]
pub struct TelemetryConfig {
    pub endpoint: String,
    pub auth_token: String,
    pub operator_domain: String,
}

#[cfg(feature = "acme")]
#[derive(Debug, Clone, Deserialize)]
pub struct AcmeConfig {
    pub domains: Vec<String>,
    pub contact: Vec<String>,
    #[serde(default)]
    pub directory_url: Option<String>,
}

#[cfg(feature = "acme")]
impl AcmeConfig {
    pub fn into_rustls_config(
        self,
        storage_dir: &Path,
    ) -> tokio_rustls_acme::AcmeConfig<std::io::Error, std::io::Error> {
        let cache_dir = storage_dir.join("acme");
        let config = tokio_rustls_acme::AcmeConfig::new(self.domains)
            .contact(self.contact)
            .cache(tokio_rustls_acme::caches::DirCache::new(cache_dir));
        match self.directory_url {
            Some(url) => config.directory(url),
            None => config.directory_lets_encrypt(true),
        }
    }
}

#[cfg(feature = "access-control")]
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct AccessControlConfig {
    pub geo_db_path: Option<PathBuf>,
    pub blocked_regions: Vec<String>,
    pub blocked_addresses_path: Option<PathBuf>,
    pub blocked_addresses_url: Option<String>,
    pub blocked_addresses_refresh_secs: Option<u64>,
    pub enable_v1: bool,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            listener: "[::]:8080".parse().expect("valid default listener address"),
            storage_dir: PathBuf::from("./data"),
            timeout: Duration::from_secs(30),
            #[cfg(feature = "telemetry")]
            telemetry: None,
            #[cfg(feature = "acme")]
            acme: None,
            #[cfg(feature = "access-control")]
            access_control: None,
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
    pub fn new(listener: ListenerAddress, storage_dir: PathBuf, timeout: Duration) -> Self {
        Self {
            listener,
            storage_dir,
            timeout,
            #[cfg(feature = "telemetry")]
            telemetry: None,
            #[cfg(feature = "acme")]
            acme: None,
            #[cfg(feature = "access-control")]
            access_control: None,
        }
    }

    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        config::Config::builder()
            // Add from optional config file
            .add_source(File::from(path).required(false))
            // Add from the environment (with a prefix of PJ)
            // Nested values are separated with a double underscore,
            // e.g. `PJ_ACME__DOMAINS=payjo.in`
            .add_source(
                config::Environment::with_prefix("PJ")
                    .separator("__")
                    .prefix_separator("_")
                    .list_separator(",")
                    .with_list_parse_key("acme.domains")
                    .with_list_parse_key("acme.contact")
                    .with_list_parse_key("access_control.blocked_regions")
                    .try_parsing(true),
            )
            .build()?
            .try_deserialize()
    }
}
