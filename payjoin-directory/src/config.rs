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
    pub db_host: String,
    pub ohttp_keys: PathBuf, // TODO OhttpConfig struct with rotation params, etc
    #[cfg(feature = "acme")]
    pub acme: AcmeConfig,
}

#[cfg(feature = "acme")]
#[derive(Debug, Clone, Deserialize)]
pub struct AcmeConfig {
    pub domain: String,
    pub contact: String,
    pub lets_encrypt_production: bool,
    pub cache_dir: PathBuf, // TODO Option?
}

#[cfg(feature = "acme")]
impl From<AcmeConfig> for tokio_rustls_acme::AcmeConfig<std::io::Error, std::io::Error> {
    fn from(acme_config: AcmeConfig) -> Self {
        tokio_rustls_acme::AcmeConfig::new([acme_config.domain])
            .contact_push(acme_config.contact)
            .cache(tokio_rustls_acme::caches::DirCache::new(acme_config.cache_dir))
            .directory_lets_encrypt(acme_config.lets_encrypt_production)
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
            metrics_listen_addr: built_config.get("metrics_listen_addr")?,
            timeout: Duration::from_secs(built_config.get("timeout")?),
            db_host: built_config.get("db_host")?,
            ohttp_keys: built_config.get("ohttp_keys")?,
            #[cfg(feature = "acme")]
            acme: AcmeConfig {
                domain: built_config.get("acme.domain")?,
                contact: built_config.get("acme.contact")?,
                lets_encrypt_production: built_config.get("acme.lets_encrypt_production")?,
                cache_dir: built_config.get("acme.cache_dir")?,
            },
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
        .set_override_option("db_host", Some(cli.db_host.to_owned()))?
        .set_override_option("ohttp_keys", Some(cli.ohttp_keys.to_string_lossy().into_owned()))?;

    #[cfg(feature = "acme")]
    let config = config
        .set_override_option("acme.domain", Some(cli.acme_domain.to_owned()))?
        .set_override_option("acme.contact", Some(cli.acme_contact.to_owned()))?
        .set_override_option("acme.lets_encrypt_production", Some(cli.lets_encrypt_production))?
        .set_override_option(
            "acme.cache_dir",
            Some(cli.acme_cache_dir.to_string_lossy().into_owned()),
        )?;

    Ok(config)
}
