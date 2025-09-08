use std::path::PathBuf;

use anyhow::Result;
use config::builder::DefaultState;
use config::{ConfigError, File, FileFormat};
use payjoin::bitcoin::FeeRate;
use payjoin::Version;
use serde::Deserialize;
use url::Url;

use crate::cli::{Cli, Commands};
use crate::db;

const CONFIG_DIR: &str = "payjoin-cli";

type Builder = config::builder::ConfigBuilder<DefaultState>;

#[derive(Debug, Clone, Deserialize)]
pub struct BitcoindConfig {
    pub rpchost: Url,
    pub cookie: Option<PathBuf>,
    pub rpcuser: String,
    pub rpcpassword: String,
}

#[cfg(feature = "v1")]
#[derive(Debug, Clone, Deserialize)]
pub struct V1Config {
    pub port: u16,
    pub pj_endpoint: Url,
}

#[cfg(feature = "v2")]
#[derive(Debug, Clone, Deserialize)]
pub struct V2Config {
    #[serde(deserialize_with = "deserialize_ohttp_keys_from_path")]
    pub ohttp_keys: Option<payjoin::OhttpKeys>,
    pub ohttp_relays: Vec<Url>,
    pub pj_directory: Url,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "version")]
pub enum VersionConfig {
    #[cfg(feature = "v1")]
    #[serde(rename = "v1")]
    V1(V1Config),
    #[cfg(feature = "v2")]
    #[serde(rename = "v2")]
    V2(V2Config),
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub db_path: PathBuf,
    pub max_fee_rate: Option<FeeRate>,
    pub bitcoind: BitcoindConfig,
    #[serde(skip)]
    pub version: Option<VersionConfig>,
    #[cfg(feature = "_manual-tls")]
    pub root_certificate: Option<PathBuf>,
    #[cfg(feature = "_manual-tls")]
    pub certificate_key: Option<PathBuf>,
}

impl Config {
    /// Check for multiple version flags and return the highest precedence version
    fn determine_version(cli: &Cli) -> Result<Version, ConfigError> {
        let mut selected_version = None;

        // Check for BIP77 (v2)
        if cli.flags.bip77.unwrap_or(false) {
            selected_version = Some(Version::Two);
        }

        // Check for BIP78 (v1)
        if cli.flags.bip78.unwrap_or(false) {
            if selected_version.is_some() {
                return Err(ConfigError::Message(
                    "Multiple version flags specified. Please use only one of: --bip77, --bip78"
                        .to_string(),
                ));
            }
            selected_version = Some(Version::One);
        }

        if let Some(version) = selected_version {
            return Ok(version);
        };

        // If no version explicitly selected, use default based on available features
        #[cfg(feature = "v2")]
        return Ok(Version::Two);
        #[cfg(all(feature = "v1", not(feature = "v2")))]
        return Ok(Version::One);
        #[cfg(not(any(feature = "v1", feature = "v2")))]
        return Err(ConfigError::Message(
            "No valid version available - must compile with v1 or v2 feature".to_string(),
        ));
    }

    pub(crate) fn new(cli: &Cli) -> Result<Self, ConfigError> {
        let mut config = config::Config::builder();
        config = add_bitcoind_defaults(config, cli)?;
        config = add_common_defaults(config, cli)?;

        let version = Self::determine_version(cli)?;

        match version {
            Version::One => {
                #[cfg(feature = "v1")]
                {
                    config = add_v1_defaults(config, cli)?;
                }
                #[cfg(not(feature = "v1"))]
                return Err(ConfigError::Message(
                    "BIP78 (v1) selected but v1 feature not enabled".to_string(),
                ));
            }
            Version::Two => {
                #[cfg(feature = "v2")]
                {
                    config = add_v2_defaults(config, cli)?;
                }
                #[cfg(not(feature = "v2"))]
                return Err(ConfigError::Message(
                    "BIP77 (v2) selected but v2 feature not enabled".to_string(),
                ));
            }
        }

        config = handle_subcommands(config, cli)?;

        if let Some(config_dir) = dirs::config_dir() {
            let global_config_path = config_dir.join(CONFIG_DIR).join("config.toml");
            config = config.add_source(File::from(global_config_path).required(false));
        }

        config = config.add_source(File::new("config.toml", FileFormat::Toml).required(false));
        let built_config = config.build()?;

        let mut config = Config {
            db_path: built_config.get("db_path")?,
            max_fee_rate: built_config.get("max_fee_rate").ok(),
            bitcoind: built_config.get("bitcoind")?,
            version: None,
            #[cfg(feature = "_manual-tls")]
            root_certificate: built_config.get("root_certificate").ok(),
            #[cfg(feature = "_manual-tls")]
            certificate_key: built_config.get("certificate_key").ok(),
        };

        match version {
            Version::One => {
                #[cfg(feature = "v1")]
                {
                    match built_config.get::<V1Config>("v1") {
                        Ok(v1) => {
                            if v1.pj_endpoint.port().is_none() != (v1.port == 0) {
                                return Err(ConfigError::Message(
                                    "If --port is 0, --pj-endpoint may not have a port".to_owned(),
                                ));
                            }

                            config.version = Some(VersionConfig::V1(v1))
                        }
                        Err(e) =>
                            return Err(ConfigError::Message(format!(
                                "Valid V1 configuration is required for BIP78 mode: {e}"
                            ))),
                    }
                }
                #[cfg(not(feature = "v1"))]
                return Err(ConfigError::Message(
                    "BIP78 (v1) selected but v1 feature not enabled".to_string(),
                ));
            }
            Version::Two => {
                #[cfg(feature = "v2")]
                {
                    match built_config.get::<V2Config>("v2") {
                        Ok(v2) => config.version = Some(VersionConfig::V2(v2)),
                        Err(e) =>
                            return Err(ConfigError::Message(format!(
                                "Valid V2 configuration is required for BIP77 mode: {e}"
                            ))),
                    }
                }
                #[cfg(not(feature = "v2"))]
                return Err(ConfigError::Message(
                    "BIP77 (v2) selected but v2 feature not enabled".to_string(),
                ));
            }
        }

        if config.version.is_none() {
            return Err(ConfigError::Message(
                "No valid version configuration found for the specified mode".to_string(),
            ));
        }

        tracing::debug!("App config: {config:?}");
        Ok(config)
    }

    #[cfg(feature = "v2")]
    pub fn save_config(cli: &Cli) -> Result<(), anyhow::Error> {
        let version = Self::determine_version(cli)
            .map_err(|e| anyhow::anyhow!("Failed to determine version: {e}"))?;

        if version != Version::Two {
            return Err(anyhow::anyhow!("--set-config is only available for bip77 (v2) mode"));
        }

        if cli.ohttp_relays.is_none() || cli.pj_directory.is_none() {
            return Err(anyhow::anyhow!(
                "--set-config requires ALL of: \
                 --pj-directory, --ohttp-relays"
            ));
        }

        let cookie_provided = cli.cookie_file.is_some();
        let rpc_provided =
            cli.rpcuser.is_some() && cli.rpcpassword.is_some() && cli.rpchost.is_some();

        // Ensure all required parameters are present

        if !(cookie_provided || rpc_provided) {
            return Err(anyhow::anyhow!(
                "--set-config requires ALL of: \
                 --rpcuser, --rpcpassword, --rpchost, or \
                 --cookie-file"
            ));
        }

        // Build the TOML map , this feels a bit hacky but it works
        let mut toml_map = toml::map::Map::new();
        let mut bitcoind_map = toml::map::Map::new();

        bitcoind_map.insert("rpcuser".into(), toml::Value::String(cli.rpcuser.clone().unwrap()));
        bitcoind_map
            .insert("rpcpassword".into(), toml::Value::String(cli.rpcpassword.clone().unwrap()));
        bitcoind_map.insert(
            "rpchost".into(),
            toml::Value::String(cli.rpchost.clone().unwrap().to_string()),
        );
        toml_map.insert("bitcoind".into(), toml::Value::Table(bitcoind_map));

        let mut v2_map = toml::map::Map::new();
        v2_map.insert(
            "pj_directory".into(),
            toml::Value::String(cli.pj_directory.as_ref().unwrap().to_string()),
        );
        let relay_list: Vec<toml::Value> = cli
            .ohttp_relays
            .as_ref()
            .unwrap()
            .iter()
            .map(|url| toml::Value::String(url.to_string()))
            .collect();
        v2_map.insert("ohttp_relays".into(), toml::Value::Array(relay_list));
        toml_map.insert("v2".into(), toml::Value::Table(v2_map));

        let toml_content = toml::Value::Table(toml_map);
        let toml_str = toml::to_string_pretty(&toml_content)?;

        let config_path = std::env::current_dir()?.join("config.toml");
        let final_path = if !config_path.exists() {
            if let Some(config_dir) = dirs::config_dir() {
                let global_dir = config_dir.join(CONFIG_DIR);
                std::fs::create_dir_all(&global_dir)?;
                global_dir.join("config.toml")
            } else {
                config_path
            }
        } else {
            config_path
        };

        std::fs::write(final_path, toml_str)?;
        Ok(())
    }

    #[cfg(feature = "v1")]
    pub fn v1(&self) -> Result<&V1Config, anyhow::Error> {
        match &self.version {
            Some(VersionConfig::V1(v1_config)) => Ok(v1_config),
            #[allow(unreachable_patterns)]
            _ => Err(anyhow::anyhow!("V1 configuration is required for BIP78 mode")),
        }
    }

    #[cfg(feature = "v2")]
    pub fn v2(&self) -> Result<&V2Config, anyhow::Error> {
        match &self.version {
            Some(VersionConfig::V2(v2_config)) => Ok(v2_config),
            #[allow(unreachable_patterns)]
            _ => Err(anyhow::anyhow!("V2 configuration is required for v2 mode")),
        }
    }
}

/// Set up default values and CLI overrides for Bitcoin RPC connection settings
fn add_bitcoind_defaults(config: Builder, cli: &Cli) -> Result<Builder, ConfigError> {
    // Set default values
    let config = config
        .set_default("bitcoind.rpchost", "http://localhost:18443")?
        .set_default("bitcoind.cookie", None::<String>)?
        .set_default("bitcoind.rpcuser", "bitcoin")?
        .set_default("bitcoind.rpcpassword", "")?;

    // Override config values with command line arguments if applicable
    let rpchost = cli.rpchost.as_ref().map(|s| s.as_str());
    let cookie_file = cli.cookie_file.as_ref().map(|p| p.to_string_lossy().into_owned());
    let rpcuser = cli.rpcuser.as_deref();
    let rpcpassword = cli.rpcpassword.as_deref();

    config
        .set_override_option("bitcoind.rpchost", rpchost)?
        .set_override_option("bitcoind.cookie", cookie_file)?
        .set_override_option("bitcoind.rpcuser", rpcuser)?
        .set_override_option("bitcoind.rpcpassword", rpcpassword)
}

fn add_common_defaults(config: Builder, cli: &Cli) -> Result<Builder, ConfigError> {
    let db_path = cli.db_path.as_ref().map(|p| p.to_string_lossy().into_owned());
    config.set_default("db_path", db::DB_PATH)?.set_override_option("db_path", db_path)
}

#[cfg(feature = "v1")]
fn add_v1_defaults(config: Builder, cli: &Cli) -> Result<Builder, ConfigError> {
    // Set default values
    let config = config
        .set_default("v1.port", 3000_u16)?
        .set_default("v1.pj_endpoint", "https://localhost:3000")?;

    // Override config values with command line arguments if applicable
    let pj_endpoint = cli.pj_endpoint.as_ref().map(|s| s.as_str());

    config
        .set_override_option("v1.port", cli.port)?
        .set_override_option("v1.pj_endpoint", pj_endpoint)
}

/// Set up default values and CLI overrides for v2-specific settings
#[cfg(feature = "v2")]
fn add_v2_defaults(config: Builder, cli: &Cli) -> Result<Builder, ConfigError> {
    // Set default values
    let config = config
        .set_default("v2.pj_directory", "https://payjo.in")?
        .set_default("v2.ohttp_keys", None::<String>)?;

    // Override config values with command line arguments if applicable
    let pj_directory = cli.pj_directory.as_ref().map(|s| s.as_str());
    let ohttp_keys = cli.ohttp_keys.as_ref().map(|p| p.to_string_lossy().into_owned());
    let ohttp_relays = cli
        .ohttp_relays
        .as_ref()
        .map(|urls| urls.iter().map(|url| url.as_str()).collect::<Vec<_>>());

    config
        .set_override_option("v2.pj_directory", pj_directory)?
        .set_override_option("v2.ohttp_keys", ohttp_keys)?
        .set_override_option("v2.ohttp_relays", ohttp_relays)
}

/// Handles configuration overrides based on CLI subcommands
fn handle_subcommands(config: Builder, cli: &Cli) -> Result<Builder, ConfigError> {
    #[cfg(feature = "_manual-tls")]
    let config = {
        config
            .set_override_option(
                "root_certificate",
                Some(cli.root_certificate.as_ref().map(|s| s.to_string_lossy().into_owned())),
            )?
            .set_override_option(
                "certificate_key",
                Some(cli.certificate_key.as_ref().map(|s| s.to_string_lossy().into_owned())),
            )?
    };
    match &cli.command {
        Commands::Send { .. } => Ok(config),
        Commands::Receive {
            #[cfg(feature = "v1")]
            port,
            #[cfg(feature = "v1")]
            pj_endpoint,
            #[cfg(feature = "v2")]
            pj_directory,
            #[cfg(feature = "v2")]
            ohttp_keys,
            ..
        } => {
            #[cfg(feature = "v1")]
            let config = config
                .set_override_option("v1.port", port.map(|p| p.to_string()))?
                .set_override_option("v1.pj_endpoint", pj_endpoint.as_ref().map(|s| s.as_str()))?;
            #[cfg(feature = "v2")]
            let config = config
                .set_override_option("v2.pj_directory", pj_directory.as_ref().map(|s| s.as_str()))?
                .set_override_option(
                    "v2.ohttp_keys",
                    ohttp_keys.as_ref().map(|s| s.to_string_lossy().into_owned()),
                )?;
            Ok(config)
        }
        #[cfg(feature = "v2")]
        Commands::Resume => Ok(config),
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
            .map_err(|e| serde::de::Error::custom(format!("Failed to read ohttp_keys file: {e}")))
            .and_then(|bytes| {
                payjoin::OhttpKeys::decode(&bytes).map_err(|e| {
                    serde::de::Error::custom(format!("Failed to decode ohttp keys: {e}"))
                })
            })
            .map(Some),
    }
}
