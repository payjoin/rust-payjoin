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


type Builder = config::builder::ConfigBuilder<DefaultState>;

#[derive(Debug, Parser)]
#[command(
    version = env!("CARGO_PKG_VERSION"),
    about = "Payjoin - bitcoin scaling, savings, and privacy by default",
    long_about = None, 
    subcommand_required = true
)]
pub struct Cli {
    #[command(flatten)]
    pub flags: Flags,
    // TODO: Make the config from the cli optional
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


#[derive(Debug, Clone, Deserialize, Parser)]
pub struct Flags {
    #[arg(long = "bip77", help = "Use BIP77 (v2) protocol (default)", action = clap::ArgAction::SetTrue)]
    pub bip77: Option<bool>,
    #[arg(long = "bip78", help = "Use BIP78 (v1) protocol", action = clap::ArgAction::SetTrue)]
    pub bip78: Option<bool>
}

#[derive(Debug, Clone, Deserialize, Parser)]
pub struct RawBitcoindConfig {
    #[arg(
        long,
        short = 'r',
        num_args(1),
        help = "The URL of the Bitcoin RPC host, e.g. regtest default is http://localhost:18443"
    )]
    pub rpchost: Option<Url>,
    #[arg(
        long = "cookie-file",
        short = 'c',
        num_args(1),
        help = "Path to the cookie file of the bitcoin node"
    )]
    pub cookie: Option<PathBuf>,
    #[arg(long = "rpcuser", num_args(1), help = "The username for the bitcoin node")]
    pub rpcuser: Option<String>,
    #[arg(long = "rpcpassword", num_args(1), help = "The password for the bitcoin node")]
    pub rpcpassword: Option<String>,
}


#[derive(Debug, Clone, Deserialize)]
pub struct BitcoindConfig {
    pub rpchost: Url,
    pub cookie: Option<PathBuf>,
    pub rpcuser: String,
    pub rpcpassword: String,
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
    pub ohttp_relay: Url,
    pub pj_directory: Url,
}

#[cfg(feature = "v2")]
#[derive(Debug, Clone, Deserialize, Parser)]
pub struct RawV2Config {
    #[serde(deserialize_with = "deserialize_ohttp_keys_from_path")]
    #[arg(long = "ohttp-keys", help = "The path to the ohttp keys file")]
    pub ohttp_keys: Option<payjoin::OhttpKeys>,
    #[arg(long = "ohttp-relay", help = "The URL of the ohttp relay")]
    pub ohttp_relay: Option<Url>,
    #[arg(long = "pj-directory", help = "The directory to store payjoin requests")]
    pub pj_directory: Option<Url>,
}

#[derive(Debug, Clone, Deserialize, Parser)]
pub struct RawConfig {
    
    #[arg(long, short = 'd', help = "Sets a custom database path")]
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
pub struct ValidatedConfig {
    pub db_path: PathBuf,
    pub max_fee_rate: Option<FeeRate>,
    pub bitcoind: BitcoindConfig,

    pub bip78: bool,
    pub bip77: bool,

    #[cfg(feature = "v1")]
    pub v1: V1Config,

    #[cfg(feature = "v2")]
    pub v2: V2Config,
}



impl ValidatedConfig {
    pub(crate) fn new(cli: &Cli) -> Result<Self, ConfigError> {
        let mut config_builder = config::Config::builder();
        config_builder = add_bitcoind_defaults(config_builder, cli)?;
        config_builder = add_common_defaults(config_builder, cli)?;

        if cli.flags.bip78.unwrap_or(false) {
            #[cfg(feature = "v1")]
            {
                config_builder = add_v1_defaults(config_builder)?;
            }
            #[cfg(not(feature = "v1"))]
            {
                return Err(ConfigError::Message(
                    "BIP78 (v1) selected but v1 feature not enabled".to_string(),
                ));
            }
        } else {
            #[cfg(feature = "v2")]
            {
                config_builder = add_v2_defaults(config_builder)?;
            }
            #[cfg(not(feature = "v2"))]
            {
                return Err(ConfigError::Message(
                    "BIP77 (v2) selected but v2 feature not enabled".to_string(),
                ));
            }
        }

        config_builder = handle_subcommands(config_builder, cli)?;

        let config = config_builder.build()?.try_deserialize()?;

        Ok(config)
    }
}

/// Set up config -> cli overrides -> defaults for Bitcoin RPC connection settings
fn add_bitcoind_defaults(config: Builder, cli: &Cli) -> Result<Builder, ConfigError> {
    // Set defaults
    let config = config.set_default("bitcoind.rpchost", "http://localhost:18443")?
        .set_default("bitcoind.rpcuser", "bitcoin")?
        .set_default("bitcoind.rpcpassword", "")?;

    // Override config values with command line arguments if applicable
    if let Some(bitcoind) = &cli.config.bitcoind {
        let rpchost = bitcoind.rpchost.as_ref().map(|s| s.as_str());
        let cookie = bitcoind.cookie.as_ref().map(|p| p.to_string_lossy().into_owned());
        let rpcuser = bitcoind.rpcuser.as_deref();
        let rpcpassword = bitcoind.rpcpassword.as_deref();

        config
            .set_override_option("bitcoind.rpchost", rpchost)?
            .set_override_option("bitcoind.cookie", cookie)?
            .set_override_option("bitcoind.rpcuser", rpcuser)?
            .set_override_option("bitcoind.rpcpassword", rpcpassword)
    } else {
        Ok(config)
    }
}

/// Set up default values and CLI overrides for common settings shared between v1 and v2
fn add_common_defaults(config: Builder, cli: &Cli) -> Result<Builder, ConfigError> {
    let db_path = cli.config.db_path.as_ref().map(|p| p.to_string_lossy().into_owned());
    config.set_default("db_path", db::DB_PATH)?.set_override_option("db_path", db_path)
}

/// Set up default values for v1-specific settings when v2 is not enabled
#[cfg(feature = "v1")]
fn add_v1_defaults(config: Builder) -> Result<Builder, ConfigError> {
    config
        .set_default("bip78", true)?
        .set_default("bip77", false)?
        .set_default("v1.port", 3000_u16)?
        .set_default("v1.pj_endpoint", "https://localhost:3000")
}

/// Set up default values and CLI overrides for v2-specific settings
#[cfg(feature = "v2")]
fn add_v2_defaults(config: Builder) -> Result<Builder, ConfigError> {
    config
        .set_default("bip77", true)?
        .set_default("bip78", false)?
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
