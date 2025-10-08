use std::env;
use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    version = env!("CARGO_PKG_VERSION"),
    about = "Payjoin Directory Server",
    long_about = None,
)]
pub struct Cli {
    #[arg(long, short = 'p', env = "PJ_DIR_PORT", help = "The port to bind [default: 8080]")]
    pub port: Option<u16>, // TODO tokio_listener::ListenerAddressLFlag

    #[arg(long, env = "PJ_METRIC_PORT", help = "The port to bind for prometheus metrics export")]
    pub metrics_port: Option<u16>, // TODO tokio_listener::ListenerAddressLFlag

    #[arg(
        long,
        env = "PJ_DIR_TIMEOUT_SECS",
        help = "The timeout for long polling operations [default: 30]"
    )]
    pub timeout: Option<u64>,

    #[arg(
        long = "storage-dir",
        env = "PJ_STORAGE_DIR",
        help = "A directory for writing mailbox data."
    )]
    pub storage_dir: Option<PathBuf>,

    #[arg(
        long = "ohttp-keys",
        env = "PJ_OHTTP_KEY_DIR",
        help = "The ohttp key config file path [default: ohttp_keys]"
    )]
    pub ohttp_keys: Option<PathBuf>,
}
