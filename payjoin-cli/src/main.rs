use std::path::PathBuf;

use anyhow::Result;
use app::config::Config;
use app::App as AppTrait;
use clap::Parser;
use cli::{Cli, Commands};

mod app;
mod cli;
mod db;

const CONFIG_DIR: &str = "payjoin-cli";

#[cfg(not(any(feature = "v1", feature = "v2")))]
compile_error!("At least one of the features ['v1', 'v2'] must be enabled");

fn find_config_path() -> Option<PathBuf> {
    // Look for a config.toml in the current working directory first
    // if not found, look for a config.toml in .config/payjoin-cli directory
    let cwd = std::env::current_dir().ok()?;
    let local_config = cwd.join("config.toml");
    if local_config.exists() {
        return Some(local_config);
    }
    let config_dir = dirs::config_dir()?;
    let payjoin_config = config_dir.join(CONFIG_DIR).join("config.toml");
    if payjoin_config.exists() {
        Some(payjoin_config)
    } else {
        None
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let cli = Cli::parse();
    let config_path = find_config_path();
    let config = Config::new(&cli, config_path)?;

    #[allow(clippy::if_same_then_else)]
    let app: Box<dyn AppTrait> = if cli.flags.bip78.unwrap_or(false) {
        #[cfg(feature = "v1")]
        {
            Box::new(crate::app::v1::App::new(config)?)
        }
        #[cfg(not(feature = "v1"))]
        {
            anyhow::bail!(
                "BIP78 (v1) support is not enabled in this build. Recompile with --features v1"
            )
        }
    } else if cli.flags.bip77.unwrap_or(false) {
        #[cfg(feature = "v2")]
        {
            Box::new(crate::app::v2::App::new(config)?)
        }
        #[cfg(not(feature = "v2"))]
        {
            anyhow::bail!(
                "BIP77 (v2) support is not enabled in this build. Recompile with --features v2"
            )
        }
    } else {
        #[cfg(feature = "v2")]
        {
            Box::new(crate::app::v2::App::new(config)?)
        }
        #[cfg(all(feature = "v1", not(feature = "v2")))]
        {
            Box::new(crate::app::v1::App::new(config)?)
        }
        #[cfg(not(any(feature = "v1", feature = "v2")))]
        {
            anyhow::bail!("No valid version available - must compile with v1 or v2 feature")
        }
    };

    match &cli.command {
        Commands::Send { bip21, fee_rate } => {
            app.send_payjoin(bip21, *fee_rate).await?;
        }
        Commands::Receive { amount, .. } => {
            app.receive_payjoin(*amount).await?;
        }
        #[cfg(feature = "v2")]
        Commands::Resume => {
            app.resume_payjoins().await?;
        }
    };

    Ok(())
}
