use anyhow::{Context, Result};
use clap::ArgMatches;
use config::{Config, File, FileFormat};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub(crate) struct AppConfig {
    pub bitcoind_rpchost: String,
    pub bitcoind_cookie: Option<String>,
    pub bitcoind_rpcuser: String,
    pub bitcoind_rpcpass: String,

    // send-only
    pub danger_accept_invalid_certs: bool,

    // receive-only
    pub pj_host: String,
    pub pj_endpoint: String,
    pub sub_only: bool,
}

impl AppConfig {
    pub(crate) fn new(matches: &ArgMatches) -> Result<Self> {
        let builder = Config::builder()
            .set_default("bitcoind_rpchost", "http://localhost:18443")?
            .set_default("bitcoind_cookie", None::<String>)?
            .set_default("bitcoind_rpcuser", "bitcoin")?
            .set_default("bitcoind_rpcpass", "")?
            .set_default("danger_accept_invalid_certs", false)?
            .set_default("pj_host", "0.0.0.0:3000")?
            .set_default("pj_endpoint", "https://localhost:3010")?
            .set_default("sub_only", false)?
            .add_source(File::new("config.toml", FileFormat::Toml))
            .set_override_option(
                "bitcoind_rpchost",
                matches.get_one::<String>("rpchost").map(|s| s.as_str()),
            )?
            .set_override_option(
                "bitcoind_cookie",
                matches.get_one::<String>("cookie_file").map(|s| s.as_str()),
            )?;
        let builder = match matches.subcommand() {
            Some(("send", matches)) => builder.set_override_option(
                "danger_accept_invalid_certs",
                matches.get_one::<bool>("DANGER_ACCEPT_INVALID_CERTS").map(|s| *s),
            )?,
            Some(("receive", matches)) => builder
                .set_override_option(
                    "pj_endpoint",
                    matches.get_one::<String>("endpoint").map(|s| s.as_str()),
                )?
                .set_override_option("sub_only", matches.get_one::<bool>("sub_only").map(|s| *s))?,
            _ => unreachable!(), // If all subcommands are defined above, anything else is unreachabe!()
        };
        let app_conf = builder.build()?;
        app_conf.try_deserialize().context("Failed to deserialize config")
    }
}
