use anyhow::Result;
use clap::{value_parser, Parser, Subcommand};
use config::builder::DefaultState;
use config::ConfigError;
use payjoin::bitcoin::amount::ParseAmountError;
use payjoin::bitcoin::{Amount, FeeRate};
use serde::Deserialize;
use std::path::PathBuf;
use url::Url;

use crate::db;

#[derive(Debug, Parser)]
#[command(version = env!("CARGO_PKG_VERSION"), about = "Payjoin - bitcoin scaling, savings, and privacy by default", long_about = None)]
pub struct Cli {
    // Make the config from the cli optional
    #[command(flatten)]
    pub config: RawConfig,
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
        #[arg(required = true, value_parser = parse_amount_in_sat)]
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
pub struct RawBitcoindConfig {
    #[arg(
        long,
        short = 'r',
        help = "The URL of the Bitcoin RPC host, e.g. regtest default is http://localhost:18443"
    )]
    pub rpchost: Option<Url>,
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
    pub rpcuser: Option<String>,
    #[arg(
        long,
        short = 'p',
        help = "The RPC password to use for authentication. Mutually exclusive with --cookie"
    )]
    pub rpcpassword: Option<String>,
}

#[cfg(feature = "v1")]
#[derive(Debug, Clone, Deserialize, Parser)]
pub struct RawV1Config {
    #[arg(long, short = 't', help = "The port of the payjoin V1 server to listen on.")]
    pub port: Option<u16>,
    #[arg(
        long,
        short = 'e',
        help = "The URL endpoint of the payjoin V1 server, e.g. https://localhost:3000"
    )]
    pub pj_endpoint: Option<Url>,
}

#[cfg(feature = "v2")]
#[derive(Debug, Clone, Deserialize, Parser)]
pub struct RawV2Config {
    #[serde(deserialize_with = "deserialize_ohttp_keys_from_path")]
    #[arg(long = "ohttp-keys", short = 'k', help = "The path to the ohttp keys file")]
    pub ohttp_keys: Option<payjoin::OhttpKeys>,
    #[arg(long = "ohttp-relay", short = 'r', help = "The URL of the ohttp relay")]
    pub ohttp_relay: Option<Url>,
    #[arg(long = "pj-directory", short = 'd', help = "The directory to store payjoin requests")]
    pub pj_directory: Option<Url>,
}

#[derive(Debug, Clone, Deserialize, Parser)]
pub struct RawConfig {
    #[arg(
        long = "bip77",
        help = "Use BIP77 (v2) protocol (default)",
        conflicts_with = "bip78",
        action = clap::ArgAction::SetTrue
    )]
    pub bip77: Option<bool>,

    #[arg(
        long = "bip78",
        help = "Use BIP78 (v1) protocol",
        conflicts_with = "bip77",
        action = clap::ArgAction::SetTrue
    )]
    pub bip78: Option<bool>,

    #[arg(
        long,
        short = 'd',
        help = "Sets a custom database path. Defaults to ~/.config/payjoin-cli"
    )]
    pub db_path: Option<PathBuf>,

    #[arg(long = "max-fee-rate", short = 'f', help = "The maximum fee rate to accept in sat/vB")]
    pub max_fee_rate: Option<FeeRate>,

    #[command(flatten)]
    pub bitcoind: Option<RawBitcoindConfig>,

    #[cfg(feature = "v1")]
    #[command(flatten)]
    pub v1: Option<RawV1Config>,

    #[cfg(feature = "v2")]
    #[command(flatten)]
    pub v2: Option<RawV2Config>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BitcoindConfig {
    pub rpchost: Url,
    pub cookie: Option<PathBuf>,
    pub rpcuser: String,
    pub rpcpassword: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValidatedConfig {
    pub bip77: bool,
    pub bip78: bool,
    pub db_path: PathBuf,
    pub max_fee_rate: Option<FeeRate>,
    pub bitcoind: BitcoindConfig,

    #[cfg(feature = "v1")]
    pub v1: V1Config,

    #[cfg(feature = "v2")]
    pub v2: V2Config,
}

#[derive(Debug, Clone, Deserialize)]
pub struct V1Config {
    pub port: u16,
    pub pj_endpoint: Url,
}

#[derive(Debug, Clone, Deserialize)]
pub struct V2Config {
    #[serde(deserialize_with = "deserialize_ohttp_keys_from_path")]
    pub ohttp_keys: Option<payjoin::OhttpKeys>,
    pub ohttp_relay: Url,
    pub pj_directory: Url,
}

impl ValidatedConfig {
    /// Version flags in order of precedence (newest to oldest)
    const VERSION_FLAGS: &'static [(&'static str, u8)] = &[("bip77", 2), ("bip78", 1)];

    /// Check for multiple version flags and return the highest precedence version
    fn determine_version(cli: &Cli) -> Result<u8, ConfigError> {
        let mut selected_version = None;
        for _ in Self::VERSION_FLAGS.iter() {
            #[cfg(feature = "v2")]
            if cli.config.bip77.is_some() {
                if selected_version.is_some() {
                    return Err(ConfigError::Message(
                        "Multiple version flags specified. Please use only one of: --bip77, --bip78"
                        .to_string()
                    ));
                }
                selected_version = Some(2);
            }

            #[cfg(feature = "v1")]
            if cli.config.bip78.is_some() {
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

    pub(crate) fn new(cli: &Cli) -> Result<Self> {
        let mut config_builder = config::Config::builder();
        config_builder = add_bitcoind_defaults(config_builder, cli)?;
        config_builder = add_common_defaults(config_builder, cli)?;
        let version = Self::determine_version(cli)?;

        match version {
            1 => {
                #[cfg(feature = "v1")]
                {
                    config_builder = add_v1_defaults(config_builder)?;
                }
                #[cfg(not(feature = "v1"))]
                return Err(ConfigError::Message(
                    "BIP78 (v1) selected but v1 feature not enabled".to_string(),
                ));
            }
            2 => {
                #[cfg(feature = "v2")]
                {
                    config_builder = add_v2_defaults(config_builder)?;
                }
                #[cfg(not(feature = "v2"))]
                return Err(ConfigError::Message(
                    "BIP77 (v2) selected but v2 feature not enabled".to_string(),
                ));
            }
            _ => unreachable!("determine_version() should only return 1 or 2"),
        }

        config_builder = handle_subcommands(config_builder, cli)?;
        let config = config_builder.build()?.try_deserialize()?;

        Ok(config)
    }

    // #[cfg(feature = "v1")]
    // pub fn v1(&self) -> Result<&V1Config, anyhow::Error> {
    //     match &self.version {
    //         Some(VersionConfig::V1(v1_config)) => Ok(v1_config),
    //         #[allow(unreachable_patterns)]
    //         _ => Err(anyhow::anyhow!("V1 configuration is required for BIP78 mode")),
    //     }
    // }
    //
    // #[cfg(feature = "v2")]
    // pub fn v2(&self) -> Result<&V2Config, anyhow::Error> {
    //     match &self.version {
    //         Some(VersionConfig::V2(v2_config)) => Ok(v2_config),
    //         #[allow(unreachable_patterns)]
    //         _ => Err(anyhow::anyhow!("V2 configuration is required for v2 mode")),
    //     }
    // }
}

// pub fn load_config() -> Result<RawConfig, ConfigError> {
//     let mut config = config::Config::builder();
//     // let config.add_source(File::with_name("config").format(FileFormat::Toml).required(false)).build()?;
//     config = config.add_source(File::with_name("config").format(FileFormat::Toml).required(false));
//     config.build()?.try_deserialize()
// }

// Validate bitcoind settings
// 1. override config values with command line arguments where applicable
// 2. if neither command line or config values are set, use default values where applicable
// 3. for those that should not have default values because there's no
//    standard, return an error

/// Set up config -> cli overrides -> defaults for Bitcoin RPC connection settings
fn add_bitcoind_defaults(config: Builder, cli: &Cli) -> Result<Builder, ConfigError> {
    // FIXME: unwrap shouldn't be used?

    // Override config values with command line arguments if applicable
    let bitcoind = &cli.config.bitcoind.clone().unwrap();
    let rpchost = bitcoind.rpchost.as_ref().map(|s| s.as_str());
    let cookie = bitcoind.cookie.as_ref().map(|p| p.to_string_lossy().into_owned());
    let rpcuser = bitcoind.rpcuser.as_ref().map(|s| s.as_str());
    let rpcpassword = bitcoind.rpcpassword.as_ref().map(|s| s.as_str());

    config
        .set_override_option("bitcoind.rpchost", rpchost)?
        .set_override_option("bitcoind.cookie", cookie)?
        .set_override_option("bitcoind.rpcuser", rpcuser)?
        .set_override_option("bitcoind.rpcpassword", rpcpassword)
}

/// Set up default values and CLI overrides for common settings shared between v1 and v2
fn add_common_defaults(config: Builder, cli: &Cli) -> Result<Builder, ConfigError> {
    let db_path = cli.config.db_path.as_ref().map(|p| p.to_string_lossy().into_owned());
    config.set_default("db_path", db::DB_PATH)?.set_override_option("db_path", db_path)
}

/// Set up default values for v1-specific settings when v2 is not enabled
#[cfg(feature = "v1")]
fn add_v1_defaults(config: Builder) -> Result<Builder, ConfigError> {
    config.set_default("v1.port", 3000_u16)?.set_default("v1.pj_endpoint", "https://localhost:3000")
}

/// Set up default values and CLI overrides for v2-specific settings
#[cfg(feature = "v2")]
fn add_v2_defaults(config: Builder) -> Result<Builder, ConfigError> {
    config
        .set_default("v2.ohttp_relay", "https://pj.bobspacebkk.com")?
        .set_default("v2.pj_directory", "https://payjo.in")?
        .set_default("v2.ohttp_keys", None::<String>)
}

/// Handles configuration overrides based on CLI subcommands
fn handle_subcommands(config: Builder, cli: &Cli) -> Result<Builder, ConfigError> {
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

fn parse_amount_in_sat(s: &str) -> Result<Amount, ParseAmountError> {
    Amount::from_str_in(s, payjoin::bitcoin::Denomination::Satoshi)
}

fn parse_fee_rate_in_sat_per_vb(s: &str) -> Result<FeeRate, std::num::ParseFloatError> {
    let fee_rate_sat_per_vb: f32 = s.parse()?;
    let fee_rate_sat_per_kwu = fee_rate_sat_per_vb * 250.0_f32;
    Ok(FeeRate::from_sat_per_kwu(fee_rate_sat_per_kwu.ceil() as u64))
}
