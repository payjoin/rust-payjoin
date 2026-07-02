#[cfg(all(feature = "v2", feature = "asmap"))]
use std::fmt;
#[cfg(all(feature = "v2", feature = "asmap"))]
use std::net::IpAddr;
use std::path::PathBuf;
#[cfg(all(feature = "v2", feature = "asmap"))]
use std::sync::Arc;

use anyhow::Result;
use config::builder::DefaultState;
use config::{ConfigError, File, FileFormat};
use payjoin::bitcoin::FeeRate;
use payjoin::{Url, Version};
use serde::Deserialize;

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

#[cfg(all(feature = "v2", feature = "asmap"))]
#[derive(Clone)]
pub struct LoadedAsmap {
    map: Arc<::asmap::Asmap>,
}

#[cfg(all(feature = "v2", feature = "asmap"))]
impl LoadedAsmap {
    #[allow(dead_code)]
    pub fn lookup(&self, ip: IpAddr) -> u32 { self.map.lookup(ip) }

    pub fn as_bytes(&self) -> &[u8] { self.map.as_bytes() }
}

#[cfg(all(feature = "v2", feature = "asmap"))]
impl<'de> Deserialize<'de> for LoadedAsmap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let path = PathBuf::deserialize(deserializer)?;
        let map = ::asmap::Asmap::from_file(&path).map_err(|e| {
            serde::de::Error::custom(format!(
                "Failed to load v2.asmap.asmap_file {}: {e}",
                path.display()
            ))
        })?;
        Ok(LoadedAsmap { map: Arc::new(map) })
    }
}

#[cfg(all(feature = "v2", feature = "asmap"))]
impl fmt::Debug for LoadedAsmap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoadedAsmap").field("bytes", &self.as_bytes().len()).finish()
    }
}

#[cfg(all(feature = "v2", feature = "asmap"))]
#[derive(Debug, Clone, Deserialize)]
pub struct AsmapConfig {
    #[serde(rename = "asmap_file")]
    #[allow(dead_code)]
    pub asmap: LoadedAsmap,
    #[serde(default)]
    pub user_public_ips: Vec<IpAddr>,
    #[serde(default)]
    pub user_asns: Vec<u32>,
}

#[cfg(all(feature = "v2", feature = "asmap"))]
impl AsmapConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.user_public_ips.is_empty() && self.user_asns.is_empty() {
            return Err(ConfigError::Message(
                "v2.asmap requires at least one of user_public_ips or user_asns".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "v2")]
#[derive(Debug, Clone, Deserialize)]
pub struct V2Config {
    #[serde(deserialize_with = "deserialize_ohttp_keys_from_path")]
    pub ohttp_keys: Option<payjoin::OhttpKeys>,
    pub ohttp_relays: Vec<Url>,
    pub pj_directories: Vec<Url>,
    #[cfg(feature = "asmap")]
    #[serde(default)]
    pub asmap: Option<AsmapConfig>,
}

#[cfg(feature = "v2")]
impl V2Config {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.pj_directories.is_empty() {
            return Err(ConfigError::Message(
                "At least one v2 trusted directory is required".to_owned(),
            ));
        }

        #[cfg(feature = "asmap")]
        if let Some(asmap) = &self.asmap {
            asmap.validate()?;
        }

        Ok(())
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum VersionConfig {
    #[cfg(feature = "v1")]
    V1(V1Config),
    #[cfg(feature = "v2")]
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
        if cli.flags.bip77 {
            selected_version = Some(Version::Two);
        }

        // Check for BIP78 (v1)
        if cli.flags.bip78 {
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

        let mut config_file_found = false;
        let mut config_file_paths = Vec::new();

        if let Some(config_dir) = dirs::config_dir() {
            let global_config_path = config_dir.join(CONFIG_DIR).join("config.toml");
            if global_config_path.exists() {
                config_file_found = true;
            }
            config_file_paths.push(global_config_path.display().to_string());
            config = config.add_source(File::from(global_config_path).required(false));
        }

        let local_config_path = std::path::Path::new("config.toml");
        if local_config_path.exists() {
            config_file_found = true;
        }
        config_file_paths.push("config.toml (current directory)".to_string());
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
                            if v1.port == 0 && v1.pj_endpoint.port().is_some() {
                                return Err(ConfigError::Message(
                                    "If --port is 0, --pj-endpoint may not have a port".to_owned(),
                                ));
                            }

                            config.version = Some(VersionConfig::V1(v1))
                        }
                        Err(e) => {
                            let hint = if config_file_found {
                                String::new()
                            } else {
                                format!(
                                    "\nNo config file found. Searched: {}. \
                                     Create a config.toml or provide configuration via CLI arguments.",
                                    config_file_paths.join(", ")
                                )
                            };
                            return Err(ConfigError::Message(format!(
                                "Valid V1 configuration is required for BIP78 mode: {e}{hint}"
                            )));
                        }
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
                    match load_v2_config(&built_config) {
                        Ok(v2) => {
                            if v2.ohttp_relays.len() < 2 {
                                tracing::warn!(
                                    "Only one OHTTP relay is configured. Add more ohttp_relays to improve privacy."
                                );
                            }
                            if v2.pj_directories.len() < 2 {
                                tracing::warn!(
                                    "Only one payjoin directory is configured. Add more pj_directories to enable fallback."
                                );
                            }
                            config.version = Some(VersionConfig::V2(v2))
                        }
                        Err(e) => {
                            let hint = if config_file_found {
                                String::new()
                            } else {
                                format!(
                                    "\nNo config file found. Searched: {}. \
                                     Create a config.toml or provide configuration via CLI arguments.",
                                    config_file_paths.join(", ")
                                )
                            };
                            return Err(ConfigError::Message(format!(
                                "Valid V2 configuration is required for BIP77 mode: {e}{hint}"
                            )));
                        }
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

        tracing::trace!("App config: {config:?}");
        Ok(config)
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
        .set_default("v2.pj_directories", vec!["https://payjo.in", "https://lets.payjo.in"])?
        .set_default("v2.ohttp_keys", None::<String>)?;

    // Override config values with command line arguments if applicable
    let pj_directories = cli
        .pj_directories
        .as_ref()
        .map(|urls| urls.iter().map(|url| url.as_str()).collect::<Vec<_>>());
    let ohttp_keys = cli.ohttp_keys.as_ref().map(|p| p.to_string_lossy().into_owned());
    let ohttp_relays = cli
        .ohttp_relays
        .as_ref()
        .map(|urls| urls.iter().map(|url| url.as_str()).collect::<Vec<_>>());

    config
        .set_override_option("v2.pj_directories", pj_directories)?
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
            pj_directories,
            #[cfg(feature = "v2")]
            ohttp_keys,
            ..
        } => {
            #[cfg(feature = "v1")]
            let config = config
                .set_override_option("v1.port", port.map(|p| p.to_string()))?
                .set_override_option(
                    "v1.pj_endpoint",
                    pj_endpoint.clone().map(|s| s.to_string()),
                )?;
            #[cfg(feature = "v2")]
            let config = config
                .set_override_option(
                    "v2.pj_directories",
                    pj_directories
                        .as_ref()
                        .map(|urls| urls.iter().map(|url| url.as_str()).collect::<Vec<_>>()),
                )?
                .set_override_option(
                    "v2.ohttp_keys",
                    ohttp_keys.as_ref().map(|s| s.to_string_lossy().into_owned()),
                )?;
            Ok(config)
        }
        #[cfg(feature = "v2")]
        Commands::Resume => Ok(config),
        #[cfg(feature = "v2")]
        Commands::History => Ok(config),
        #[cfg(feature = "v2")]
        Commands::Cancel { .. } => Ok(config),
    }
}

#[cfg(feature = "v2")]
fn load_v2_config(built_config: &config::Config) -> Result<V2Config, ConfigError> {
    #[cfg(not(feature = "asmap"))]
    if built_config.get_table("v2.asmap").is_ok() {
        return Err(ConfigError::Message(
            "This build does not include ASMap support. Recompile with --features asmap".to_owned(),
        ));
    }

    let v2 = built_config.get::<V2Config>("v2")?;
    v2.validate()?;
    Ok(v2)
}

#[cfg(feature = "v2")]
fn deserialize_ohttp_keys_from_path<'de, D>(
    deserializer: D,
) -> Result<Option<payjoin::OhttpKeys>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let path: Option<PathBuf> = Option::deserialize(deserializer)?;
    match path {
        None => Ok(None),
        Some(path) => {
            let bytes = std::fs::read(&path).map_err(|e| {
                serde::de::Error::custom(format!(
                    "Failed to read ohttp_keys file {}: {e}",
                    path.display()
                ))
            })?;
            let keys = payjoin::OhttpKeys::decode(&bytes).map_err(|e| {
                serde::de::Error::custom(format!(
                    "Failed to decode ohttp keys from {}: {e}",
                    path.display()
                ))
            })?;
            Ok(Some(keys))
        }
    }
}

#[cfg(all(test, feature = "v1"))]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::cli::Cli;

    fn cli(port: &str, endpoint: &str) -> Cli {
        Cli::parse_from([
            "payjoin-cli",
            "--bip78",
            "--port",
            port,
            "--pj-endpoint",
            endpoint,
            "receive",
            "50000",
        ])
    }

    #[test]
    fn rejects_random_port_with_explicit_endpoint_port() {
        let err = Config::new(&cli("0", "https://example.com:443/")).unwrap_err();
        assert!(err.to_string().contains("port"), "unexpected error: {err}");
    }

    #[test]
    fn accepts_random_port_with_implicit_endpoint_port() {
        Config::new(&cli("0", "https://example.com/")).unwrap();
    }

    #[test]
    fn accepts_explicit_port_with_implicit_endpoint_port() {
        Config::new(&cli("3000", "https://example.com/")).unwrap();
    }

    #[test]
    fn accepts_explicit_port_with_matching_explicit_endpoint_port() {
        Config::new(&cli("3000", "https://example.com:3000/")).unwrap();
    }

    #[test]
    fn accepts_explicit_port_with_different_explicit_endpoint_port() {
        Config::new(&cli("3000", "https://example.com:443/")).unwrap();
    }
}
