use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use config::builder::DefaultState;
use config::{ConfigError, File, FileFormat};
use serde::Deserialize;

type Builder = config::builder::ConfigBuilder<DefaultState>;

use crate::cli::Cli;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub listen_addr: String,         // TODO tokio_listener::ListenerAddressLFlag
    pub metrics_listen_addr: String, // TODO tokio_listener::ListenerAddressLFlag
    pub timeout: Duration,
    #[cfg(feature = "redis")]
    pub db_host: String,
    #[cfg(not(feature = "redis"))]
    pub storage_dir: PathBuf,
    pub ohttp_keys: PathBuf, // TODO OhttpConfig struct with rotation params, etc
}

impl Config {
    pub fn new(cli: &Cli) -> Result<Self, ConfigError> {
        let mut config = config::Config::builder();
        config = add_defaults(config, cli)?;

        // what directory should this reside in? require explicit --config-file? ~/.config? /etc?
        config = config.add_source(File::new("config.toml", FileFormat::Toml).required(false));

        let built_config = config.build()?;

        Ok(Config {
            listen_addr: built_config.get("listen_addr")?,
            metrics_listen_addr: built_config.get("metrics_listen_addr")?,
            timeout: Duration::from_secs(built_config.get("timeout")?),
            #[cfg(feature = "redis")]
            db_host: built_config.get("storage_dir")?,
            #[cfg(not(feature = "redis"))]
            storage_dir: built_config.get("storage_dir")?,
            ohttp_keys: built_config.get("ohttp_keys")?,
        })
    }
}

fn add_defaults(config: Builder, cli: &Cli) -> Result<Builder, ConfigError> {
    let config = config
        .set_override_option("listen_addr", Some(format!("[::]:{}", cli.port)))?
        .set_override_option(
            "metrics_listen_addr",
            Some(format!("localhost:{}", cli.metrics_port)),
        )?
        .set_override_option("timeout", Some(cli.timeout))?
        .set_override_option("ohttp_keys", Some(cli.ohttp_keys.to_string_lossy().into_owned()))?;

    #[cfg(feature = "redis")]
    let config = config.set_override_option("db_host", Some(cli.db_host.to_owned()))?;

    #[cfg(not(feature = "redis"))]
    let config = config
        .set_override_option("storage_dir", Some(cli.storage_dir.to_string_lossy().into_owned()))?;

    Ok(config)
}
