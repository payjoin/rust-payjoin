use std::env;
use std::path::PathBuf;

use clap::Parser;
use tokio_listener::ListenerAddressLFlag;

#[derive(Debug, Parser)]
#[command(
    version = env!("CARGO_PKG_VERSION"),
    about = "Payjoin Directory Server",
    long_about = None,
)]
pub struct Cli {
    #[clap(flatten)]
    pub listen: ListenerAddressLFlag,

    #[arg(long = "metrics-listen-addr")]
    pub metrics_listen_addr: Option<String>,

    #[cfg(feature = "acme")]
    #[clap(flatten)]
    pub acme: AcmeCli,

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

#[cfg(feature = "acme")]
#[derive(Debug, Parser)]
pub struct AcmeCli {
    #[arg(long = "acme-domain", help = "The domain for which to request a certificate using ACME")]
    pub domain: Option<String>,

    #[arg(
        long = "acme-contact",
        help = "Contact information for ACME usage (e.g. 'mailto:admin@example.com')"
    )]
    pub contact: Option<String>,

    #[arg(long, help = "Whether to use the staging environment [default: production]")]
    pub lets_encrypt_staging: Option<bool>,

    #[arg(long = "acme-cache-dir", help = "What directory to use for the ACME cache")]
    pub cache_dir: Option<PathBuf>,
}
