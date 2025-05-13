use anyhow::Result;
use app::config::{Cli, Commands, ValidatedConfig};
use app::App as AppTrait;
use clap::Parser;
use payjoin::bitcoin::FeeRate;

mod app;
mod db;

#[cfg(not(any(feature = "v1", feature = "v2")))]
compile_error!("At least one of the features ['v1', 'v2'] must be enabled");

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // Validate the cli args and structure is correct
    let cli = Cli::parse();

    // Merge the config file with the command line, overriding config values with command line values
    // where applicable, validate the result
    let validated_config = ValidatedConfig::new(&cli)?;

    // let app = app::App::new(validated_config);
    //

    // if flag bip78 is passed, create a v1 app
    // let app: Box<dyn AppTrait> = if validated_config.bip78 {
    //     #[cfg(feature = "v1")]
    //     Box::new(app::v1::App::new(validated_config));
    //     #[cfg(not(feature = "v1"))]
    //     unreachable!()
    // } else {
    //     #[cfg(feature = "v2")]
    //     Box::new(app::v2::App::new(validated_config));
    //     #[cfg(not(feature = "v2"))]
    //     unreachable!()
    // };
    #[allow(clippy::if_same_then_else)]
    let app: Box<dyn AppTrait> = if validated_config.bip78 {
        #[cfg(feature = "v1")]
        {
            Box::new(crate::app::v1::App::new(validated_config)?)
        }
        #[cfg(not(feature = "v1"))]
        {
            anyhow::bail!(
                "BIP78 (v1) support is not enabled in this build. Recompile with --features v1"
            )
        }
    } else if validated_config.bip77 {
        #[cfg(feature = "v2")]
        {
            Box::new(crate::app::v2::App::new(validated_config)?)
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
            Box::new(crate::app::v2::App::new(validated_config)?)
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

    // --- If code made it to this point we can assume the config validated ---
    match &cli.command {
        // Some(("send", sub_matches)) => {
        //     let bip21 = sub_matches.get_one::<String>("BIP21").context("Missing BIP21 argument")?;
        //     let fee_rate = sub_matches
        //         .get_one::<FeeRate>("fee_rate")
        //         .context("Missing --fee-rate argument")?;
        //     app.send_payjoin(bip21, *fee_rate).await?;
        // }
        // Some(("receive", sub_matches)) => {
        //     let amount =
        //         sub_matches.get_one::<Amount>("AMOUNT").context("Missing AMOUNT argument")?;
        //     app.receive_payjoin(*amount).await?;
        // }
        // #[cfg(feature = "v2")]
        // Some(("resume", _)) => {
        //     if matches.get_flag("bip78") {
        //         anyhow::bail!("Resume command is only available with BIP77 (v2)");
        //     }
        //     println!("resume");
        //     app.resume_payjoins().await?;
        // }
        Commands::Send { bip21, fee_rate } => {
            //
            let fee = fee_rate
                .unwrap_or_else(|| FeeRate::from_sat_per_vb(2).unwrap_or(FeeRate::BROADCAST_MIN));
            app.send_payjoin(bip21, fee).await?;
        }
        Commands::Receive { amount, .. } => {
            app.receive_payjoin(*amount).await?;
        }
        #[cfg(feature = "v2")]
        Commands::Resume => {
            app.resume_payjoins().await?;
        }
    }

    Ok(())
}
