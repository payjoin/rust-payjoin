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
    #[cfg(feature = "acme")]
    pub acme: Option<AcmeConfig>,
}

#[cfg(feature = "acme")]
#[derive(Debug, Clone, Deserialize)]
pub struct AcmeConfig {
    pub domain: String,
    pub contact: String,
    pub lets_encrypt_staging: bool,
    pub cache_dir: PathBuf,
}

#[cfg(feature = "acme")]
impl From<AcmeConfig> for tokio_rustls_acme::AcmeConfig<std::io::Error, std::io::Error> {
    fn from(acme_config: AcmeConfig) -> Self {
        tokio_rustls_acme::AcmeConfig::new([acme_config.domain])
            .contact_push(acme_config.contact)
            .cache(tokio_rustls_acme::caches::DirCache::new(acme_config.cache_dir))
            .directory_lets_encrypt(!acme_config.lets_encrypt_staging)
    }
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
            #[cfg(feature = "acme")]
            acme: if built_config.get_table("acme").is_ok() {
                Some(AcmeConfig {
                    domain: built_config.get("acme.domain")?,
                    contact: built_config.get("acme.contact")?,
                    lets_encrypt_staging: built_config.get("acme.lets_encrypt_staging")?,
                    cache_dir: built_config.get("acme.cache_dir")?,
                })
            } else {
                None
            },
        })
    }
}

fn add_defaults(config: Builder, cli: &Cli) -> Result<Builder, ConfigError> {
    let config = config
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
        )?;

    #[cfg(feature = "acme")]
    let config = if cli.acme.domain.is_some() {
        config
            .set_override_option("acme.domain", cli.acme.domain.clone())?
            .set_override_option("acme.contact", cli.acme.contact.clone())?
            .set_override_option("acme.lets_encrypt_staging", cli.acme.lets_encrypt_staging)?
            .set_override_option(
                "acme.cache_dir",
                cli.acme.cache_dir.clone().map(|s| s.to_string_lossy().into_owned()),
            )?
    } else {
        config
    };

    Ok(config)
}
