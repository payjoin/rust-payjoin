use std::path::PathBuf;

use anyhow::Result;
use clap::ArgMatches;
use config::{Config, ConfigError, File, FileFormat};
use payjoin::bitcoin::FeeRate;
use serde::Deserialize;
use url::Url;

use crate::db;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub bitcoind_rpchost: Url,
    pub bitcoind_cookie: Option<PathBuf>,
    pub bitcoind_rpcuser: String,
    pub bitcoind_rpcpassword: String,
    pub db_path: PathBuf,
    // receive-only
    pub max_fee_rate: Option<FeeRate>,

    // v2 only
    #[cfg(feature = "v2")]
    #[serde(deserialize_with = "deserialize_ohttp_keys_from_path")]
    pub ohttp_keys: Option<payjoin::OhttpKeys>,
    #[cfg(feature = "v2")]
    pub ohttp_relay: Url,
    #[cfg(feature = "v2")]
    pub pj_directory: Url,

    // v1 receive-only
    #[cfg(not(feature = "v2"))]
    pub port: u16,
    #[cfg(not(feature = "v2"))]
    pub pj_endpoint: Url,
}

impl AppConfig {
    pub(crate) fn new(matches: &ArgMatches) -> Result<Self, ConfigError> {
        let builder = Config::builder()
            .set_default("bitcoind_rpchost", "http://localhost:18443")?
            .set_override_option(
                "bitcoind_rpchost",
                matches.get_one::<Url>("rpchost").map(|s| s.as_str()),
            )?
            .set_default("bitcoind_cookie", None::<String>)?
            .set_override_option(
                "bitcoind_cookie",
                matches.get_one::<String>("cookie_file").map(|s| s.as_str()),
            )?
            .set_default("bitcoind_rpcuser", "bitcoin")?
            .set_override_option(
                "bitcoind_rpcuser",
                matches.get_one::<String>("rpcuser").map(|s| s.as_str()),
            )?
            .set_default("bitcoind_rpcpassword", "")?
            .set_override_option(
                "bitcoind_rpcpassword",
                matches.get_one::<String>("rpcpassword").map(|s| s.as_str()),
            )?
            .set_default("db_path", db::DB_PATH)?
            .set_override_option(
                "db_path",
                matches.get_one::<String>("db_path").map(|s| s.as_str()),
            )?
            // Subcommand defaults without which file serialization fails.
            .set_default("port", "3000")?
            .set_default("pj_endpoint", "https://localhost:3000")?
            .add_source(File::new("config.toml", FileFormat::Toml).required(false));

        #[cfg(feature = "v2")]
        let builder = builder
            .set_override_option(
                "ohttp_relay",
                matches.get_one::<Url>("ohttp_relay").map(|s| s.as_str()),
            )?
            .set_default("pj_directory", "https://payjo.in")?
            .set_default("ohttp_keys", None::<String>)?;

        let builder = match matches.subcommand() {
            Some(("send", _)) => builder,
            Some(("receive", matches)) => {
                #[cfg(not(feature = "v2"))]
                let builder = {
                    let port = matches
                        .get_one::<String>("port")
                        .map(|port| port.parse::<u16>())
                        .transpose()
                        .map_err(|_| {
                            ConfigError::Message("\"port\" must be a valid number".to_string())
                        })?;
                    builder.set_override_option("port", port)?.set_override_option(
                        "pj_endpoint",
                        matches.get_one::<Url>("pj_endpoint").map(|s| s.as_str()),
                    )?
                };

                #[cfg(feature = "v2")]
                let builder = {
                    builder
                        .set_override_option(
                            "pj_directory",
                            matches.get_one::<Url>("pj_directory").map(|s| s.as_str()),
                        )?
                        .set_override_option(
                            "ohttp_keys",
                            matches.get_one::<String>("ohttp_keys").map(|s| s.as_str()),
                        )?
                };

                let max_fee_rate = matches.get_one::<FeeRate>("max_fee_rate");
                builder.set_override_option("max_fee_rate", max_fee_rate.map(|f| f.to_string()))?
            }
            #[cfg(feature = "v2")]
            Some(("resume", _)) => builder,
            _ => unreachable!(), // If all subcommands are defined above, anything else is unreachabe!()
        };

        let config = builder.build()?;
        let app_config: AppConfig = config.try_deserialize()?;
        log::debug!("App config: {:?}", app_config);
        Ok(app_config)
    }
}

#[cfg(feature = "v2")]
fn deserialize_ohttp_keys_from_path<'de, D>(
    deserializer: D,
) -> Result<Option<payjoin::OhttpKeys>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let path_str: Option<String> = Option::deserialize(deserializer)?;

    match path_str {
        None => Ok(None),
        Some(path) => std::fs::read(path)
            .map_err(|e| serde::de::Error::custom(format!("Failed to read ohttp_keys file: {}", e)))
            .and_then(|bytes| {
                payjoin::OhttpKeys::decode(&bytes).map_err(|e| {
                    serde::de::Error::custom(format!("Failed to decode ohttp keys: {}", e))
                })
            })
            .map(Some),
    }
}
