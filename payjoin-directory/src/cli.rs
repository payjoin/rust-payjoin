use std::env;
use std::path::PathBuf;

use clap::{value_parser, Parser};

#[derive(Debug, Parser)]
#[command(
    version = env!("CARGO_PKG_VERSION"),
    about = "Payjoin Directory Server",
    long_about = None,
)]
pub struct Cli {
    #[arg(
        long,
        short = 'p',
        env = "PJ_DIR_PORT",
        default_value = "8080",
        help = "The port to bind"
    )]
    pub port: u16, // TODO tokio_listener::ListenerAddressLFlag

    #[cfg(feature = "acme")]
    #[arg(long, help = "The domain for which to request a certificate using ACME")]
    pub acme_domain: String,

    #[cfg(feature = "acme")]
    #[arg(long, help = "Contact information for ACME usage (e.g. 'mailto:admin@example.com')")]
    pub acme_contact: String,

    #[cfg(feature = "acme")]
    #[arg(
        long,
        // default_value_t = true, // FIXME doesn't generate a --no-lets-encrypt-production flag, needs workaround
        help = "Whether to use the staging or production environment"
    )]
    pub lets_encrypt_production: bool,

    #[cfg(feature = "acme")]
    #[arg(long, help = "Whether to use the staging or production environment", value_parser = value_parser!(PathBuf))]
    pub acme_cache_dir: PathBuf, // TODO Option?

    #[arg(
        long,
        env = "PJ_METRIC_PORT",
        default_value = "9090",
        help = "The port to bind for prometheus metrics export"
    )]
    pub metrics_port: u16, // TODO tokio_listener::ListenerAddressLFlag

    #[arg(
        long,
        env = "PJ_DIR_TIMEOUT_SECS",
        default_value = "30",
        help = "The timeout for long polling operations"
    )]
    pub timeout: u64,

    #[arg(
        long = "db-host",
        env = "PJ_DB_HOST",
        default_value = "localhost:6379",
        help = "The redis host to connect to"
    )]
    pub db_host: String,

    #[arg(
        long = "ohttp-keys",
        env = "PJ_OHTTP_KEY_DIR",
        help = "The ohttp key config file path",
        default_value = "ohttp_keys",
        value_parser = value_parser!(PathBuf)
    )]
    pub ohttp_keys: PathBuf,
}
