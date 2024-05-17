use anyhow::{Context, Result};
use app::config::AppConfig;
use app::App as AppTrait;
use clap::{arg, value_parser, Arg, ArgMatches, Command};
use url::Url;

mod app;

#[cfg(not(feature = "v2"))]
use app::v1::App;
#[cfg(feature = "v2")]
use app::v2::App;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let matches = cli();
    let config = AppConfig::new(&matches).with_context(|| "Failed to parse config")?;
    let app = App::new(config)?;

    match matches.subcommand() {
        Some(("send", sub_matches)) => {
            let bip21 = sub_matches.get_one::<String>("BIP21").context("Missing BIP21 argument")?;
            let fee_rate_sat_per_vb =
                sub_matches.get_one::<f32>("fee_rate").context("Missing --fee-rate argument")?;
            let is_retry = matches.get_one::<bool>("retry").unwrap_or(&false);
            app.send_payjoin(bip21, fee_rate_sat_per_vb, *is_retry).await?;
        }
        Some(("receive", sub_matches)) => {
            let amount =
                sub_matches.get_one::<String>("AMOUNT").context("Missing AMOUNT argument")?;
            let is_retry = matches.get_one::<bool>("retry").unwrap_or(&false);
            app.receive_payjoin(amount, *is_retry).await?;
        }
        _ => unreachable!(), // If all subcommands are defined above, anything else is unreachabe!()
    }

    Ok(())
}

fn cli() -> ArgMatches {
    Command::new("payjoin")
        .about("Payjoin - bitcoin scaling, savings, and privacy by default")
        .arg(
            Arg::new("rpchost")
                .long("rpchost")
                .short('r')
                .num_args(1)
                .help("The port of the bitcoin node")
                .value_parser(value_parser!(Url)),
        )
        .arg(
            Arg::new("cookie_file")
                .long("cookie-file")
                .short('c')
                .num_args(1)
                .help("Path to the cookie file of the bitcoin node"),
        )
        .arg(
            Arg::new("rpcuser")
                .long("rpcuser")
                .num_args(1)
                .help("The username for the bitcoin node"),
        )
        .arg(
            Arg::new("rpcpassword")
                .long("rpcpassword")
                .num_args(1)
                .help("The password for the bitcoin node"),
        )
        .subcommand_required(true)
        .arg(
            Arg::new("ohttp_keys")
                .long("ohttp-keys")
                .help("The ohttp key config as a base64 encoded string"),
        )
        .arg(
            Arg::new("ohttp_relay")
                .long("ohttp-relay")
                .help("The ohttp relay url")
                .value_parser(value_parser!(Url)),
        )
        .arg(
            Arg::new("retry")
                .long("retry")
                .short('e')
                .action(clap::ArgAction::SetTrue)
                .help("Retry the asynchronous payjoin request if it did not yet complete"),
        )
        .subcommand(
            Command::new("send")
                .arg_required_else_help(true)
                .arg(arg!(<BIP21> "The `bitcoin:...` payjoin uri to send to"))
                .arg_required_else_help(true)
                .arg(
                    Arg::new("fee_rate")
                        .long("fee-rate")
                        .value_name("FEE_SAT_PER_VB")
                        .help("Fee rate in sat/vB")
                        .value_parser(value_parser!(f32)),
                ),
        )
        .subcommand(
            Command::new("receive")
                .arg_required_else_help(true)
                .arg(arg!(<AMOUNT> "The amount to receive in satoshis"))
                .arg_required_else_help(true)
                .arg(
                    Arg::new("port")
                        .long("port")
                        .short('p')
                        .num_args(1)
                        .help("The local port to listen on"),
                )
                .arg(
                    Arg::new("endpoint")
                        .long("endpoint")
                        .short('e')
                        .num_args(1)
                        .help("The `pj=` endpoint to receive the payjoin request")
                        .value_parser(value_parser!(Url)),
                ),
        )
        .get_matches()
}
