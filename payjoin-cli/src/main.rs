use anyhow::Result;
use app::config::Config;
use app::App as AppTrait;
use clap::Parser;
use cli::{Cli, Commands};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

mod app;
mod cli;
mod db;

#[cfg(not(any(feature = "v1", feature = "v2")))]
compile_error!("At least one of the features ['v1', 'v2'] must be enabled");

#[tokio::main]
async fn main() -> Result<()> {
    let env_filter =
        EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy();
    tracing_subscriber::fmt().with_target(true).with_level(true).with_env_filter(env_filter).init();

    let cli = Cli::parse();
    let config = Config::new(&cli)?;

    #[allow(clippy::if_same_then_else)]
    let app: Box<dyn AppTrait> = if cli.flags.bip78.unwrap_or(false) {
        #[cfg(feature = "v1")]
        {
            Box::new(crate::app::v1::App::new(config).await?)
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
            Box::new(crate::app::v2::App::new(config).await?)
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
            Box::new(crate::app::v2::App::new(config).await?)
        }
        #[cfg(all(feature = "v1", not(feature = "v2")))]
        {
            Box::new(crate::app::v1::App::new(config).await?)
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
