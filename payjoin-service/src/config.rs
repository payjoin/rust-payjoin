use std::path::{Path, PathBuf};
use std::time::Duration;

use config::{ConfigError, File};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub port: u16,
    pub storage_dir: PathBuf,
    #[serde(deserialize_with = "deserialize_duration_secs")]
    pub timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self { port: 8080, storage_dir: PathBuf::from("./data"), timeout: Duration::from_secs(30) }
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
            .add_source(config::Environment::with_prefix("PJ"))
            .build()?
            .try_deserialize()
    }
}
