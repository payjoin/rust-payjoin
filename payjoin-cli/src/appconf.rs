use anyhow::{Context, Result};
use clap::ArgMatches;
use config::{Config, File, FileFormat};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AppConfig {
    pub bitcoind_rpchost: String,
    pub bitcoind_cookie: Option<String>,
    pub bitcoind_rpcuser: String,
    pub bitcoind_rpcpass: String,
    #[cfg(feature = "v2")]
    pub ohttp_config: String,
    #[cfg(feature = "v2")]
    pub ohttp_proxy: String,

    // receive-only
    pub pj_host: String,
    pub pj_endpoint: String,
    pub sub_only: bool,
}

impl AppConfig {
    pub(crate) fn new(matches: &ArgMatches) -> Result<Self> {
        let builder = Config::builder()
            .set_default("bitcoind_rpchost", "http://localhost:18443")?
            .set_override_option(
                "bitcoind_rpchost",
                matches.get_one::<String>("rpchost").map(|s| s.as_str()),
            )?
            .set_default("bitcoind_cookie", None::<String>)?
            .set_override_option(
                "bitcoind_cookie",
                matches.get_one::<String>("cookie_file").map(|s| s.as_str()),
            )?
            .set_default("bitcoind_rpcuser", "bitcoin")?
            .set_override_option(
                "bitcoind_rpcuser",
                matches.get_one::<String>("rpcuser").map(|s| s.as_str()),
            )?
            .set_default("bitcoind_rpcpass", "")?
            .set_override_option(
                "bitcoind_rpcpass",
                matches.get_one::<String>("rpcpass").map(|s| s.as_str()),
            )?
            // Subcommand defaults without which file serialization fails.
            .set_default("pj_host", "0.0.0.0:3000")?
            .set_default("pj_endpoint", "https://localhost:3000")?
            .set_default("sub_only", false)?
            .add_source(File::new("config.toml", FileFormat::Toml).required(false));

        #[cfg(feature = "v2")]
        let builder = builder
            .set_default("ohttp_config", "")?
            .set_override_option(
                "ohttp_config",
                matches.get_one::<String>("ohttp_config").map(|s| s.as_str()),
            )?
            .set_default("ohttp_proxy", "")?
            .set_override_option(
                "ohttp_proxy",
                matches.get_one::<String>("ohttp_proxy").map(|s| s.as_str()),
            )?;

        let builder = match matches.subcommand() {
            Some(("send", _)) => builder,
            Some(("receive", matches)) => builder
                .set_override_option(
                    "pj_host",
                    matches.get_one::<String>("port").map(|port| format!("0.0.0.0:{}", port)),
                )?
                .set_override_option(
                    "pj_endpoint",
                    matches.get_one::<String>("endpoint").map(|s| s.as_str()),
                )?
                .set_override_option("sub_only", matches.get_one::<bool>("sub_only").copied())?,
            _ => unreachable!(), // If all subcommands are defined above, anything else is unreachabe!()
        };
        let app_conf = builder.build()?;
        log::debug!("App config: {:?}", app_conf);
        app_conf.try_deserialize().context("Failed to deserialize config")
    }
}
