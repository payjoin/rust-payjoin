use std::path::PathBuf;

use clap::{value_parser, Parser, Subcommand};
use payjoin::bitcoin::amount::ParseAmountError;
use payjoin::bitcoin::{Amount, FeeRate};
use serde::Deserialize;
use url::Url;

#[derive(Debug, Clone, Deserialize, Parser)]
pub struct Flags {
    #[arg(long = "bip77", help = "Use BIP77 (v2) protocol (default)", action = clap::ArgAction::SetTrue)]
    pub bip77: Option<bool>,
    #[arg(long = "bip78", help = "Use BIP78 (v1) protocol", action = clap::ArgAction::SetTrue)]
    pub bip78: Option<bool>,
}

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

    #[command(subcommand)]
    pub command: Commands,

    #[arg(long, short = 'd', help = "Sets a custom database path")]
    pub db_path: Option<PathBuf>,

    #[arg(long = "max-fee-rate", short = 'f', help = "The maximum fee rate to accept in sat/vB")]
    pub max_fee_rate: Option<FeeRate>,

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
    pub cookie_file: Option<PathBuf>,

    #[arg(long = "rpcuser", num_args(1), help = "The username for the bitcoin node")]
    pub rpcuser: Option<String>,

    #[arg(long = "rpcpassword", num_args(1), help = "The password for the bitcoin node")]
    pub rpcpassword: Option<String>,

    #[cfg(feature = "v1")]
    #[arg(long = "port", help = "The local port to listen on")]
    pub port: Option<u16>,

    #[cfg(feature = "v1")]
    #[arg(long = "pj-endpoint", help = "The `pj=` endpoint to receive the payjoin request", value_parser = value_parser!(Url))]
    pub pj_endpoint: Option<Url>,

    #[cfg(feature = "v2")]
    #[arg(long = "ohttp-relays", help = "One or more ohttp relay URLs, comma-separated", value_parser = value_parser!(Url))]
    pub ohttp_relays: Option<Vec<Url>>,

    #[cfg(feature = "v2")]
    #[arg(long = "ohttp-keys", help = "The ohttp key config file path", value_parser = value_parser!(PathBuf))]
    pub ohttp_keys: Option<PathBuf>,

    #[cfg(feature = "v2")]
    #[arg(long = "pj-directory", help = "The directory to store payjoin requests", value_parser = value_parser!(Url))]
    pub pj_directory: Option<Url>,
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
        #[arg(long = "ohttp-keys", value_parser = value_parser!(PathBuf))]
        ohttp_keys: Option<PathBuf>,
    },
    /// Resume pending payjoins (BIP77/v2 only)
    #[cfg(feature = "v2")]
    Resume,
}

pub fn parse_amount_in_sat(s: &str) -> Result<Amount, ParseAmountError> {
    Amount::from_str_in(s, payjoin::bitcoin::Denomination::Satoshi)
}

pub fn parse_fee_rate_in_sat_per_vb(s: &str) -> Result<FeeRate, std::num::ParseFloatError> {
    let fee_rate_sat_per_vb: f32 = s.parse()?;
    let fee_rate_sat_per_kwu = fee_rate_sat_per_vb * 250.0_f32;
    Ok(FeeRate::from_sat_per_kwu(fee_rate_sat_per_kwu.ceil() as u64))
}
