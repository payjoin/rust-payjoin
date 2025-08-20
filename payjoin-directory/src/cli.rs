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

    #[arg(
        long,
        short = 'p',
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

    #[cfg(feature = "redis")]
    #[arg(long = "db-host", env = "PJ_DB_HOST", help = "The redis host to connect to")]
    pub db_host: String,

    #[cfg(not(feature = "redis"))]
    #[arg(
        long = "storage-dir",
        env = "PJ_STORAGE_DIR",
        help = "A directory for writing mailbox data."
    )]
    pub storage_dir: PathBuf,

    #[arg(
        long = "ohttp-keys",
        env = "PJ_OHTTP_KEY_DIR",
        help = "The ohttp key config file path",
        default_value = "ohttp_keys",
        value_parser = value_parser!(PathBuf)
    )]
    pub ohttp_keys: PathBuf,
}
