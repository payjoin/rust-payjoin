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
    pub listen_addr: String, // TODO tokio_listener::ListenerAddressLFlag
    pub metrics_listen_addr: Option<String>, // TODO tokio_listener::ListenerAddressLFlag
    pub timeout: Duration,
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
            metrics_listen_addr: built_config.get("metrics_listen_addr").ok(),
            timeout: Duration::from_secs(built_config.get("timeout")?),
            storage_dir: built_config.get("storage_dir")?,
            ohttp_keys: built_config.get("ohttp_keys")?,
        })
    }
}

fn add_defaults(config: Builder, cli: &Cli) -> Result<Builder, ConfigError> {
    config
        .set_default("listen_addr", "[::]:8080")?
        .set_override_option("listen_addr", cli.port.map(|port| format!("[::]:{}", port)))?
        .set_default("metrics_listen_addr", Option::<String>::None)?
        .set_override_option(
            "metrics_listen_addr",
            cli.metrics_port.map(|port| format!("localhost:{}", port)),
        )?
        .set_default("timeout", Some(30))?
        .set_override_option("timeout", cli.timeout)?
        .set_default("ohttp_keys", "ohttp_keys")?
        .set_override_option(
            "ohttp_keys",
            cli.ohttp_keys.clone().map(|s| s.to_string_lossy().into_owned()),
        )?
        .set_override_option(
            "storage_dir",
            cli.storage_dir.clone().map(|s| s.to_string_lossy().into_owned()),
        )
}
