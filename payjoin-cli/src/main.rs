use anyhow::{Context, Result};
use clap::{arg, Arg, ArgMatches, Command};

mod app;
use app::{App, AppConfig};
use tungstenite::{connect, Message};
use url::Url;

fn main() -> Result<()> {
    env_logger::init();

    let matches = cli();
    let config = AppConfig::new(&matches)?;
    let app = App::new(config)?;

    match matches.subcommand() {
        Some(("send", sub_matches)) => {
            let bip21 = sub_matches.get_one::<String>("BIP21").context("Missing BIP21 argument")?;
            app.send_payjoin(bip21)?;
        }
        Some(("receive", sub_matches)) => {


            let amount =
                sub_matches.get_one::<String>("AMOUNT").context("Missing AMOUNT argument")?;
            if *sub_matches.get_one::<bool>("reelay").context("Missing REELAY argument")? {
                println!("REElay");
                let (mut socket, response) =
                    connect(Url::parse("ws://localhost:3012/socket").unwrap()).expect("Can't connect");

                println!("Connected to the server");
                println!("Response HTTP code: {}", response.status());
                println!("Response contains the following headers:");
                for (ref header, _value) in response.headers() {
                    println!("* {}", header);
                }
                socket.write_message(Message::Text("Hello WebSocket".into())).unwrap();
                loop {
                    let msg = socket.read_message().expect("Error reading message");
                    println!("Received: {}", msg);
                }
            } else {
                app.receive_payjoin(amount)?;
            }
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
                .arg(Arg::new("DANGER_ACCEPT_INVALID_CERTS")
                    .hide(true)
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
                .arg(Arg::new("reelay")
                    .long("reelay")
                    .short('r')
                    .required(false)
                    .value_parser(clap::value_parser!(bool))
                    .num_args(0..=1)
                    .default_missing_value("false")
                    .help("Have a REElay host the payjoin endpoint on our behalf 😡"))
                .arg(Arg::new("sub_only")
                    .long("sub-only")
                    .short('s')
                    .num_args(0)
                    .required(false)
                    .hide(true)
                    .help("Use payjoin like a payment code, no hot wallet required. Only substitute outputs. Don't contribute inputs."))
        )
        .get_matches()
}
