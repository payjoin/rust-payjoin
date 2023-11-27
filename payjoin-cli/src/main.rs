use anyhow::{Context, Result};
use clap::{arg, value_parser, Arg, ArgMatches, Command};

mod app;
use app::{App, AppConfig};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let matches = cli();
    let config = AppConfig::new(&matches)?;
    let app = App::new(config)?;

    match matches.subcommand() {
        Some(("send", sub_matches)) => {
            let bip21 = sub_matches.get_one::<String>("BIP21").context("Missing BIP21 argument")?;
            let fee_rate_sat_per_vb =
                sub_matches.get_one::<f32>("fee_rate").context("Missing --fee-rate argument")?;
            app.send_payjoin(bip21, fee_rate_sat_per_vb).await?;
        }
        Some(("receive", sub_matches)) => {
            let amount =
                sub_matches.get_one::<String>("AMOUNT").context("Missing AMOUNT argument")?;
            app.receive_payjoin(amount).await?;
        }
        _ => unreachable!(), // If all subcommands are defined above, anything else is unreachabe!()
    }

    Ok(())
}

fn cli() -> ArgMatches {
    Command::new("payjoin")
        .about("Transfer bitcoin and preserve your privacy")
        .arg(Arg::new("rpchost")
            .long("rpchost")
            .short('r')
            .help("The port of the bitcoin node"))
        .arg(Arg::new("cookie_file")
            .long("cookie-file")
            .short('c')
            .help("Path to the cookie file of the bitcoin node"))
        .arg(Arg::new("rpcuser")
            .long("rpcuser")
            .help("The username for the bitcoin node"))
        .arg(Arg::new("rpcpass")
            .long("rpcpass")
            .help("The password for the bitcoin node"))
        .subcommand_required(true)
        .subcommand(
            Command::new("send")
                .arg_required_else_help(true)
                .arg(arg!(<BIP21> "The `bitcoin:...` payjoin uri to send to"))
                .arg_required_else_help(true)
                .arg(Arg::new("fee_rate")
                    .long("fee-rate")
                    .value_name("FEE_SAT_PER_VB")
                    .help("Fee rate in sat/vB")
                    .value_parser(value_parser!(f32)),
                )
                .arg(Arg::new("DANGER_ACCEPT_INVALID_CERTS")
                    .long("danger-accept-invalid-certs")
                    .hide(true)
                    .action(clap::ArgAction::SetTrue)
                    .help("Wicked dangerous! Vulnerable to MITM attacks! Accept invalid certs for the payjoin endpoint"))
        )
        .subcommand(
            Command::new("receive")
                .arg_required_else_help(true)
                .arg(arg!(<AMOUNT> "The amount to receive in satoshis"))
                .arg_required_else_help(true)
                .arg(Arg::new("port")
                    .long("host-port")
                    .short('p')
                    .help("The local port to listen on"))
                .arg(Arg::new("endpoint")
                    .long("endpoint")
                    .short('e')
                    .help("The `pj=` endpoint to receive the payjoin request"))
                .arg(Arg::new("sub_only")
                    .long("sub-only")
                    .short('s')
                    .action(clap::ArgAction::SetTrue)
                    .hide(true)
                    .help("Use payjoin like a payment code, no hot wallet required. Only substitute outputs. Don't contribute inputs."))
        )
        .get_matches()
}
