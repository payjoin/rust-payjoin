use anyhow::Result;
use clap::{value_parser, ArgMatches, Parser, Subcommand};
use config::builder::DefaultState;
use config::{ConfigError, File, FileFormat};
use payjoin::bitcoin::amount::ParseAmountError;
use payjoin::bitcoin::{Amount, FeeRate};
use serde::Deserialize;
use std::path::PathBuf;
use url::Url;

use crate::db;

#[derive(Debug, Parser)]
#[command(version = env!("CARGO_PKG_VERSION"), about = "Payjoin - bitcoin scaling, savings, and privacy by default", long_about = None)]
pub struct Cli {
    #[command(flatten)]
    pub config: Config,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Send a payjoin payment
    Send {
        /// The `bitcoin:...` payjoin uri to send to
        #[arg(required = true)]
        bip21: String,

        /// Fee rate in sat/vB
        #[arg(short, long = "fee-rate", value_parser = parse_fee_rate_in_sat_per_vb)]
        fee_rate: Option<FeeRate>,
    },
    /// Receive a payjoin payment
    Receive {
        /// The amount to receive in satoshis
        #[arg(required = true)]
        amount: Amount,

        /// The maximum effective fee rate the receiver is willing to pay (in sat/vB)
        #[arg(short, long = "max-fee-rate", value_parser = parse_fee_rate_in_sat_per_vb)]
        max_fee_rate: Option<FeeRate>,

        #[cfg(feature = "v1")]
        /// The local port to listen on
        #[arg(short, long = "port")]
        port: Option<u16>,

        #[cfg(feature = "v1")]
        /// The `pj=` endpoint to receive the payjoin request
        #[arg(long = "pj-endpoint", value_parser = value_parser!(Url))]
        pj_endpoint: Option<Url>,

        #[cfg(feature = "v2")]
        /// The directory to store payjoin requests
        #[arg(long = "pj-directory", value_parser = value_parser!(Url))]
        pj_directory: Option<Url>,

        #[cfg(feature = "v2")]
        /// The path to the ohttp keys file
        #[arg(long = "ohttp-keys", value_parser = value_parser!(Url))]
        ohttp_keys: Option<PathBuf>,
    },
    /// Resume pending payjoins (BIP77/v2 only)
    #[cfg(feature = "v2")]
    Resume,
}

type Builder = config::builder::ConfigBuilder<DefaultState>;

#[derive(Debug, Clone, Deserialize, Parser)]
pub struct BitcoindConfig {
    #[arg(
        long,
        short = 'r',
        help = "The URL of the Bitcoin RPC host, e.g. regtest default is http://localhost:18443"
    )]
    pub rpchost: Url,
    #[arg(
        long,
        short = 'c',
        help = "The cookie file to use for authentication. Mutually exclusive with --rpcuser and --rpcpassword"
    )]
    pub cookie: Option<PathBuf>,
    #[arg(
        long,
        short = 'u',
        help = "The RPC username to use for authentication. Mutually exclusive with --cookie"
    )]
    pub rpcuser: String,
    #[arg(
        long,
        short = 'p',
        help = "The RPC password to use for authentication. Mutually exclusive with --cookie"
    )]
    pub rpcpassword: String,
}

#[cfg(feature = "v1")]
#[derive(Debug, Clone, Deserialize, Parser)]
pub struct V1Config {
    #[arg(long, short = 't', help = "The port of the payjoin V1 server to listen on.")]
    pub port: u16,
    #[arg(
        long,
        short = 'e',
        help = "The URL endpoint of the payjoin V1 server, e.g. https://localhost:3000"
    )]
    pub pj_endpoint: Url,
}

#[cfg(feature = "v2")]
#[derive(Debug, Clone, Deserialize, Parser)]
pub struct V2Config {
    #[serde(deserialize_with = "deserialize_ohttp_keys_from_path")]
    #[arg(long = "ohttp-keys", short = 'k', help = "The path to the ohttp keys file")]
    pub ohttp_keys: Option<payjoin::OhttpKeys>,
    #[arg(long = "ohttp-relay", short = 'r', help = "The URL of the ohttp relay")]
    pub ohttp_relay: Url,
    #[arg(long = "pj-directory", short = 'd', help = "The directory to store payjoin requests")]
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

#[derive(Debug, Clone, Deserialize, Parser)]
pub struct Config {
    #[arg(
        long = "bip77",
        help = "Use BIP77 (v2) protocol (default)",
        conflicts_with = "bip78",
        action = clap::ArgAction::SetTrue
        )]
    pub bip77: bool,

    #[arg(
        long = "bip78",
        help = "Use BIP78 (v1) protocol",
        conflicts_with = "bip77",
        action = clap::ArgAction::SetTrue
        )]
    pub bip78: bool,

    #[arg(
        long,
        short = 'd',
        help = "Sets a custom database path. Defaults to ~/.config/payjoin-cli"
    )]
    pub db_path: PathBuf,

    #[arg(long = "max-fee-rate", short = 'f', help = "The maximum fee rate to accept in sat/vB")]
    pub max_fee_rate: Option<FeeRate>,

    #[command(flatten)]
    pub bitcoind: BitcoindConfig,

    #[serde(skip)]
    #[arg(skip)]
    pub version: Option<VersionConfig>,
}

impl Config {
    /// Version flags in order of precedence (newest to oldest)
    const VERSION_FLAGS: &'static [(&'static str, u8)] = &[("bip77", 2), ("bip78", 1)];

    /// Check for multiple version flags and return the highest precedence version
    fn determine_version(cli: &Cli) -> Result<u8, ConfigError> {
        let mut selected_version = None;
        for _ in Self::VERSION_FLAGS.iter() {
            #[cfg(feature = "v2")]
            if cli.config.bip77 {
                if selected_version.is_some() {
                    return Err(ConfigError::Message(
                            "Multiple version flags specified. Please use only one of: --bip77, --bip78"
                            .to_string()
                        ));
                }
                selected_version = Some(2);
            }

            #[cfg(feature = "v1")]
            if cli.config.bip78 {
                if selected_version.is_some() {
                    return Err(ConfigError::Message(
                            "Multiple version flags specified. Please use only one of: --bip77, --bip78"
                            .to_string()
                        ));
                }
                selected_version = Some(1);
            }
        }

        if let Some(version) = selected_version {
            return Ok(version);
        }

        #[cfg(feature = "v2")]
        return Ok(2);
        #[cfg(all(feature = "v1", not(feature = "v2")))]
        return Ok(1);

        #[cfg(not(any(feature = "v1", feature = "v2")))]
        return Err(ConfigError::Message(
            "No valid version available - must compile with v1 or v2 feature".to_string(),
        ));
    }

    // Matches should be a param that has the same return type
    // as Cli::parse
    pub(crate) fn new(cli: &Cli) -> Result<Self, ConfigError> {
        let mut builder = config::Config::builder();
        builder = add_bitcoind_defaults(builder, cli)?;
        builder = add_common_defaults(builder, cli)?;

        let version = Self::determine_version(cli)?;

        match version {
            1 => {
                #[cfg(feature = "v1")]
                {
                    builder = add_v1_defaults(builder)?;
                }
                #[cfg(not(feature = "v1"))]
                return Err(ConfigError::Message(
                    "BIP78 (v1) selected but v1 feature not enabled".to_string(),
                ));
            }
            2 => {
                #[cfg(feature = "v2")]
                {
                    builder = add_v2_defaults(builder)?;
                }
                #[cfg(not(feature = "v2"))]
                return Err(ConfigError::Message(
                    "BIP77 (v2) selected but v2 feature not enabled".to_string(),
                ));
            }
            _ => unreachable!("determine_version() should only return 1 or 2"),
        }

        builder = handle_subcommands(builder, cli)?;
        builder = builder.add_source(File::new("config.toml", FileFormat::Toml).required(false));

        let built_config = builder.build()?;

        let mut config = Config {
            db_path: built_config.get("db_path")?,
            max_fee_rate: built_config.get("max_fee_rate").ok(),
            bitcoind: built_config.get("bitcoind")?,
            version: None,
            bip77: cli.config.bip77,
            bip78: cli.config.bip78,
        };

        match version {
            1 => {
                #[cfg(feature = "v1")]
                {
                    match built_config.get::<V1Config>("v1") {
                        Ok(v1) => config.version = Some(VersionConfig::V1(v1)),
                        Err(e) => {
                            return Err(ConfigError::Message(format!(
                                "Valid V1 configuration is required for BIP78 mode: {e}"
                            )))
                        }
                    }
                }
                #[cfg(not(feature = "v1"))]
                return Err(ConfigError::Message(
                    "BIP78 (v1) selected but v1 feature not enabled".to_string(),
                ));
            }
            2 => {
                #[cfg(feature = "v2")]
                {
                    match built_config.get::<V2Config>("v2") {
                        Ok(v2) => config.version = Some(VersionConfig::V2(v2)),
                        Err(e) => {
                            return Err(ConfigError::Message(format!(
                                "Valid V2 configuration is required for BIP77 mode: {e}"
                            )))
                        }
                    }
                }
                #[cfg(not(feature = "v2"))]
                return Err(ConfigError::Message(
                    "BIP77 (v2) selected but v2 feature not enabled".to_string(),
                ));
            }
            _ => unreachable!("determine_version() should only return 1 or 2"),
        }

        if config.version.is_none() {
            return Err(ConfigError::Message(
                "No valid version configuration found for the specified mode".to_string(),
            ));
        }

        log::debug!("App config: {config:?}");
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
fn add_bitcoind_defaults(builder: Builder, cli: &Cli) -> Result<Builder, ConfigError> {
    builder
        .set_default("bitcoind.rpchost", "http://localhost:18443")?
        .set_override_option(
            "bitcoind.rpchost",
            Some(cli.config.bitcoind.rpchost.to_owned().as_str()),
        )?
        .set_default("bitcoind.cookie", None::<String>)?
        .set_override_option(
            "bitcoind.cookie",
            cli.config.bitcoind.cookie.as_ref().map(|p| p.to_string_lossy().into_owned()),
        )?
        .set_default("bitcoind.rpcuser", "bitcoin")?
        .set_override_option(
            "bitcoind.rpcuser",
            Some(cli.config.bitcoind.rpcuser.to_owned().as_str()),
        )?
        .set_default("bitcoind.rpcpassword", "")?
        .set_override_option(
            "bitcoind.rpcpassword",
            Some(cli.config.bitcoind.rpcpassword.to_owned().as_str()),
        )
}

/// Set up default values and CLI overrides for common settings shared between v1 and v2
fn add_common_defaults(builder: Builder, cli: &Cli) -> Result<Builder, ConfigError> {
    builder
        .set_default("db_path", db::DB_PATH)?
        .set_override_option("db_path", cli.config.db_path.to_str())
}

/// Set up default values for v1-specific settings when v2 is not enabled
#[cfg(feature = "v1")]
fn add_v1_defaults(builder: Builder) -> Result<Builder, ConfigError> {
    builder
        .set_default("v1.port", 3000_u16)?
        .set_default("v1.pj_endpoint", "https://localhost:3000")
}

/// Set up default values and CLI overrides for v2-specific settings
#[cfg(feature = "v2")]
fn add_v2_defaults(builder: Builder) -> Result<Builder, ConfigError> {
    builder
        .set_default("v2.ohttp_relay", "https://pj.bobspacebkk.com")?
        .set_default("v2.pj_directory", "https://payjo.in")?
        .set_default("v2.ohttp_keys", None::<String>)
}

/// Handles configuration overrides based on CLI subcommands
fn handle_subcommands(builder: Builder, cli: &Cli) -> Result<Builder, ConfigError> {
    match &cli.command {
        Commands::Send { .. } => Ok(builder),
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
            let builder = builder
                .set_override_option("v1.port", port.map(|p| p.to_string()))?
                .set_override_option("v1.pj_endpoint", pj_endpoint.as_ref().map(|s| s.as_str()))?;
            #[cfg(feature = "v2")]
            let builder = builder
                .set_override_option("v2.pj_directory", pj_directory.as_ref().map(|s| s.as_str()))?
                .set_override_option(
                    "v2.ohttp_keys",
                    ohttp_keys.as_ref().map(|s| s.to_string_lossy().into_owned()),
                )?;
            Ok(builder)
        }
        #[cfg(feature = "v2")]
        Commands::Resume => Ok(builder),
    }
}

/// Handle configuration overrides specific to the receive command
fn handle_receive_command(builder: Builder, matches: &ArgMatches) -> Result<Builder, ConfigError> {
    #[cfg(feature = "v1")]
    let builder = {
        let port = matches
            .get_one::<String>("port")
            .map(|port| port.parse::<u16>())
            .transpose()
            .map_err(|_| ConfigError::Message("\"port\" must be a valid number".to_string()))?;
        builder.set_override_option("v1.port", port)?.set_override_option(
            "v1.pj_endpoint",
            matches.get_one::<Url>("pj_endpoint").map(|s| s.as_str()),
        )?
    };

    #[cfg(feature = "v2")]
    let builder = {
        builder
            .set_override_option(
                "v2.pj_directory",
                matches.get_one::<Url>("pj_directory").map(|s| s.as_str()),
            )?
            .set_override_option(
                "v2.ohttp_keys",
                matches.get_one::<String>("ohttp_keys").map(|s| s.as_str()),
            )?
    };

    Ok(builder)
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

fn parse_amount_in_sat(s: &str) -> Result<Amount, ParseAmountError> {
    Amount::from_str_in(s, payjoin::bitcoin::Denomination::Satoshi)
}

fn parse_fee_rate_in_sat_per_vb(s: &str) -> Result<FeeRate, std::num::ParseFloatError> {
    let fee_rate_sat_per_vb: f32 = s.parse()?;
    let fee_rate_sat_per_kwu = fee_rate_sat_per_vb * 250.0_f32;
    Ok(FeeRate::from_sat_per_kwu(fee_rate_sat_per_kwu.ceil() as u64))
}
