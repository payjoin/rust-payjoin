use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Result;
use clap::ArgMatches;
use config::{Config, File, FileFormat};
use serde::Deserialize;
use url::Url;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub bitcoind_rpchost: Url,
    pub bitcoind_cookie: Option<PathBuf>,
    pub bitcoind_rpcuser: String,
    pub bitcoind_rpcpassword: String,
    #[cfg(feature = "v2")]
    pub ohttp_keys: Option<payjoin::OhttpKeys>,
    #[cfg(feature = "v2")]
    pub ohttp_relay: Url,

    // receive-only
    pub pj_host: SocketAddr,
    pub pj_endpoint: Url,
    pub sub_only: bool,
}

impl AppConfig {
    pub(crate) fn new(matches: &ArgMatches) -> Result<Self> {
        let builder = Config::builder()
            .set_default("bitcoind_rpchost", "http://localhost:18443")?
            .set_override_option(
                "bitcoind_rpchost",
                matches.get_one::<Url>("rpchost").map(|s| s.as_str()),
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
            .set_default("bitcoind_rpcpassword", "")?
            .set_override_option(
                "bitcoind_rpcpassword",
                matches.get_one::<String>("rpcpassword").map(|s| s.as_str()),
            )?
            // Subcommand defaults without which file serialization fails.
            .set_default("pj_host", "0.0.0.0:3000")?
            .set_default("pj_endpoint", "https://localhost:3000")?
            .set_default("sub_only", false)?
            .add_source(File::new("config.toml", FileFormat::Toml).required(false));

        #[cfg(feature = "v2")]
        let builder = builder
            .set_override_option(
                "ohttp_keys",
                matches.get_one::<String>("ohttp_keys").map(|s| s.as_str()),
            )?
            .set_override_option(
                "ohttp_relay",
                matches.get_one::<Url>("ohttp_relay").map(|s| s.as_str()),
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
                    matches.get_one::<Url>("endpoint").map(|s| s.as_str()),
                )?
                .set_override_option("sub_only", matches.get_one::<bool>("sub_only").copied())?,
            _ => unreachable!(), // If all subcommands are defined above, anything else is unreachabe!()
        };

        let config = builder.build()?;
        let app_config: AppConfig = config.try_deserialize()?;
        log::debug!("App config: {:?}", app_config);
        Ok(app_config)
    }
}
