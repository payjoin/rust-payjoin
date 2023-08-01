use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use bitcoincore_rpc::bitcoin::Amount;
use bitcoincore_rpc::jsonrpc::serde_json;
use bitcoincore_rpc::RpcApi;
use clap::ArgMatches;
use config::{Config, File, FileFormat};
use payjoin::bitcoin::psbt::Psbt;
use payjoin::receive::{Error, PayjoinProposal};
use payjoin::{bitcoin, PjUriExt, UriExt};
use rouille::{Request, Response};
use serde::{Deserialize, Serialize};

pub(crate) struct App {
    config: AppConfig,
    bitcoind: bitcoincore_rpc::Client,
    seen_inputs: Arc<Mutex<SeenInputs>>,
}

impl App {
    pub fn new(config: AppConfig) -> Result<Self> {
        let bitcoind = match &config.bitcoind_cookie {
            Some(cookie) => bitcoincore_rpc::Client::new(
                &config.bitcoind_rpchost,
                bitcoincore_rpc::Auth::CookieFile(cookie.into()),
            ),
            None => bitcoincore_rpc::Client::new(
                &config.bitcoind_rpchost,
                bitcoincore_rpc::Auth::UserPass(
                    config.bitcoind_rpcuser.clone(),
                    config.bitcoind_rpcpass.clone(),
                ),
            ),
        }
        .context("Failed to connect to bitcoind")?;
        let seen_inputs = Arc::new(Mutex::new(SeenInputs::new()?));
        Ok(Self { config, bitcoind, seen_inputs })
    }

    pub fn send_payjoin(&self, bip21: &str) -> Result<()> {
        use payjoin::send::Configuration;

        let link = payjoin::Uri::try_from(bip21)
            .map_err(|e| anyhow!("Failed to create URI from BIP21: {}", e))?;

        let link = link
            .assume_checked()
            .check_pj_supported()
            .map_err(|e| anyhow!("The provided URI doesn't support payjoin (BIP78): {}", e))?;

        let amount = link.amount.ok_or_else(|| anyhow!("please specify the amount in the Uri"))?;

        // wallet_create_funded_psbt requires a HashMap<address: String, Amount>
        let mut outputs = HashMap::with_capacity(1);
        outputs.insert(link.address.to_string(), amount);

        let fee_rate = bitcoin::FeeRate::from_sat_per_vb(2).ok_or(anyhow!("Invalid fee rate"))?;
        let fee_sat_per_kvb =
            fee_rate.to_sat_per_kwu().checked_mul(4).ok_or(anyhow!("Invalid fee rate"))?;
        let fee_per_kvb = Amount::from_sat(fee_sat_per_kvb);
        log::debug!("Fee rate sat/kvb: {}", fee_per_kvb.display_in(bitcoin::Denomination::Satoshi));
        let options = bitcoincore_rpc::json::WalletCreateFundedPsbtOptions {
            lock_unspent: Some(true),
            fee_rate: Some(fee_per_kvb),
            ..Default::default()
        };
        let psbt = self
            .bitcoind
            .wallet_create_funded_psbt(
                &[], // inputs
                &outputs,
                None, // locktime
                Some(options),
                None,
            )
            .context("Failed to create PSBT")?
            .psbt;
        let psbt = self
            .bitcoind
            .wallet_process_psbt(&psbt, None, None, None)
            .with_context(|| "Failed to process PSBT")?
            .psbt;
        let psbt = Psbt::from_str(&psbt).with_context(|| "Failed to load PSBT from base64")?;
        log::debug!("Original psbt: {:#?}", psbt);

        let payout_scripts = std::iter::once(link.address.script_pubkey());
        let pj_params = Configuration::recommended(&psbt, payout_scripts, fee_rate);

        let (req, ctx) = link
            .create_pj_request(psbt, pj_params)
            .with_context(|| "Failed to create payjoin request")?;
        let client = reqwest::blocking::Client::builder()
            .danger_accept_invalid_certs(self.config.danger_accept_invalid_certs)
            .build()
            .with_context(|| "Failed to build reqwest http client")?;
        let mut response = client
            .post(req.url)
            .body(req.body)
            .header("Content-Type", "text/plain")
            .send()
            .with_context(|| "HTTP request failed")?;
        // TODO display well-known errors and log::debug the rest
        let psbt =
            ctx.process_response(&mut response).with_context(|| "Failed to process response")?;
        log::debug!("Proposed psbt: {:#?}", psbt);
        let psbt = self
            .bitcoind
            .wallet_process_psbt(&serialize_psbt(&psbt), None, None, None)
            .with_context(|| "Failed to process PSBT")?
            .psbt;
        let tx = self
            .bitcoind
            .finalize_psbt(&psbt, Some(true))
            .with_context(|| "Failed to finalize PSBT")?
            .hex
            .ok_or_else(|| anyhow!("Incomplete PSBT"))?;
        let txid = self
            .bitcoind
            .send_raw_transaction(&tx)
            .with_context(|| "Failed to send raw transaction")?;
        log::info!("Transaction sent: {}", txid);
        Ok(())
    }

    pub fn receive_payjoin(self, amount_arg: &str) -> Result<()> {
        use payjoin::Uri;

        let pj_receiver_address = self.bitcoind.get_new_address(None, None)?.assume_checked();
        let amount = Amount::from_sat(amount_arg.parse()?);
        let pj_uri_string = format!(
            "{}?amount={}&pj={}",
            pj_receiver_address.to_qr_uri(),
            amount.to_btc(),
            self.config.pj_endpoint
        );
        let pj_uri = Uri::from_str(&pj_uri_string)
            .map_err(|e| anyhow!("Constructed a bad URI string from args: {}", e))?;
        let _pj_uri = pj_uri
            .assume_checked()
            .check_pj_supported()
            .map_err(|e| anyhow!("Constructed URI does not support payjoin: {}", e))?;

        println!(
            "Listening at {}. Configured to accept payjoin at BIP 21 Payjoin Uri:",
            self.config.pj_host
        );
        println!("{}", pj_uri_string);

        #[cfg(feature = "local-https")]
        let server = {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
            let cert_ser = cert.serialize_pem()?;
            let skey_ser = cert.serialize_private_key_pem().into_bytes();
            rouille::Server::new_ssl(
                self.config.pj_host.clone(),
                move |req| self.handle_web_request(req),
                cert_ser.into_bytes(),
                skey_ser,
            )
            .map_err(|e| anyhow!("Failed to create HTTPS server: {}", e))?
        };

        #[cfg(not(feature = "local-https"))]
        let server = {
            rouille::Server::new(self.config.pj_host.clone(), move |req| {
                self.handle_web_request(req)
            })
            .map_err(|e| anyhow!("Failed to create HTTP server: {}", e))?
        };

        server.run();
        Ok(())
    }

    fn handle_web_request(&self, req: &Request) -> Response {
        log::debug!("Received request: {:?}", req);
        match (req.method(), req.url().as_ref()) {
            ("GET", "/bip21") => {
                log::debug!("{:?}, {:?}", req.method(), req.raw_query_string());
                let amount = req.get_param("amount").map(|amt| {
                    Amount::from_btc(amt.parse().expect("Failed to parse amount")).unwrap()
                });
                self.handle_get_bip21(amount)
                    .map_err(|e| {
                        log::error!("Error handling request: {}", e);
                        Response::text(e.to_string()).with_status_code(500)
                    })
                    .unwrap_or_else(|err_resp| err_resp)
            }
            ("POST", _) => self
                .handle_payjoin_post(req)
                .map_err(|e| match e {
                    Error::BadRequest(e) => {
                        log::error!("Error handling request: {}", e);
                        Response::text(e.to_string()).with_status_code(400)
                    }
                    e => {
                        log::error!("Error handling request: {}", e);
                        Response::text(e.to_string()).with_status_code(500)
                    }
                })
                .unwrap_or_else(|err_resp| err_resp),
            _ => Response::empty_404(),
        }
        .with_additional_header("Access-Control-Allow-Origin", "*")
    }

    fn handle_get_bip21(&self, amount: Option<Amount>) -> Result<Response, Error> {
        let address = self
            .bitcoind
            .get_new_address(None, None)
            .map_err(|e| Error::Server(e.into()))?
            .assume_checked();
        let uri_string = if let Some(amount) = amount {
            format!(
                "{}?amount={}&pj={}",
                address.to_qr_uri(),
                amount.to_btc(),
                self.config.pj_endpoint
            )
        } else {
            format!("{}?pj={}", address.to_qr_uri(), self.config.pj_endpoint)
        };
        let uri = payjoin::Uri::try_from(uri_string.clone())
            .map_err(|_| Error::Server(anyhow!("Could not parse payjoin URI string.").into()))?;
        let _ = uri
            .assume_checked() // we just got it from bitcoind above
            .check_pj_supported()
            .map_err(|_| Error::Server(anyhow!("Created bip21 with invalid &pj=.").into()))?;
        Ok(Response::text(uri_string))
    }

    fn handle_payjoin_post(&self, req: &Request) -> Result<Response, Error> {
        let headers = Headers(req.headers());
        let proposal = payjoin::receive::UncheckedProposal::from_request(
            req.data().context("Failed to read request body").map_err(|e| {
                log::warn!("Failed to read request body: {}", e);
                Error::Server(e.into())
            })?,
            req.raw_query_string(),
            headers,
        )?;

        // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
        let _to_broadcast_in_failure_case = proposal.get_transaction_to_schedule_broadcast();

        // The network is used for checks later
        let network =
            self.bitcoind.get_blockchain_info().map_err(|e| Error::Server(e.into())).and_then(
                |info| bitcoin::Network::from_str(&info.chain).map_err(|e| Error::Server(e.into())),
            )?;

        // Receive Check 1: Can Broadcast
        let proposal = proposal.check_can_broadcast(|tx| {
            let raw_tx = bitcoin::consensus::encode::serialize_hex(&tx);
            let mempool_results = self
                .bitcoind
                .test_mempool_accept(&[raw_tx])
                .map_err(|e| Error::Server(e.into()))?;
            match mempool_results.first() {
                Some(result) => Ok(result.allowed),
                None => Err(Error::Server(
                    anyhow!("No mempool results returned on broadcast check").into(),
                )),
            }
        })?;
        log::trace!("check1");

        // Receive Check 2: receiver can't sign for proposal inputs
        let proposal = proposal.check_inputs_not_owned(|input| {
            if let Ok(address) = bitcoin::Address::from_script(input, network) {
                self.bitcoind
                    .get_address_info(&address)
                    .map(|info| info.is_mine.unwrap_or(false))
                    .map_err(|e| Error::Server(e.into()))
            } else {
                Ok(false)
            }
        })?;
        log::trace!("check2");
        // Receive Check 3: receiver can't sign for proposal inputs
        let proposal = proposal.check_no_mixed_input_scripts()?;
        log::trace!("check3");

        // Receive Check 4: have we seen this input before? More of a check for non-interactive i.e. payment processor receivers.
        let payjoin = proposal.check_no_inputs_seen_before(|input| {
            Ok(!self.insert_input_seen_before(*input).map_err(|e| Error::Server(e.into()))?)
        })?;
        log::trace!("check4");

        let mut payjoin = payjoin.identify_receiver_outputs(|output_script| {
            if let Ok(address) = bitcoin::Address::from_script(output_script, network) {
                self.bitcoind
                    .get_address_info(&address)
                    .map(|info| info.is_mine.unwrap_or(false))
                    .map_err(|e| Error::Server(e.into()))
            } else {
                Ok(false)
            }
        })?;

        if !self.config.sub_only {
            // Select receiver payjoin inputs.
            _ = try_contributing_inputs(&mut payjoin, &self.bitcoind)
                .map_err(|e| log::warn!("Failed to contribute inputs: {}", e));
        }

        let receiver_substitute_address = self
            .bitcoind
            .get_new_address(None, None)
            .map_err(|e| Error::Server(e.into()))?
            .assume_checked();
        payjoin.substitute_output_address(receiver_substitute_address);

        let payjoin_proposal_psbt = payjoin.apply_fee(Some(1))?;

        log::debug!("Extracted PSBT: {:#?}", payjoin_proposal_psbt);
        // Sign payjoin psbt
        let payjoin_base64_string = base64::encode(&payjoin_proposal_psbt.serialize());
        // `wallet_process_psbt` adds available utxo data and finalizes
        let payjoin_proposal_psbt = self
            .bitcoind
            .wallet_process_psbt(&payjoin_base64_string, None, None, Some(false))
            .map_err(|e| Error::Server(e.into()))?
            .psbt;
        let payjoin_proposal_psbt = Psbt::from_str(&payjoin_proposal_psbt)
            .context("Failed to parse PSBT")
            .map_err(|e| Error::Server(e.into()))?;
        let payjoin_proposal_psbt = payjoin.prepare_psbt(payjoin_proposal_psbt)?;
        log::debug!("Receiver's Payjoin proposal PSBT Rsponse: {:#?}", payjoin_proposal_psbt);

        let payload = base64::encode(&payjoin_proposal_psbt.serialize());
        log::info!("successful response");
        Ok(Response::text(payload))
    }

    fn insert_input_seen_before(&self, input: bitcoin::OutPoint) -> Result<bool> {
        self.seen_inputs.lock().expect("mutex lock failed").insert(input)
    }
}

struct SeenInputs {
    set: OutPointSet,
    file: std::fs::File,
}

impl SeenInputs {
    fn new() -> Result<Self> {
        // read from file
        let mut file =
            OpenOptions::new().write(true).read(true).create(true).open("seen_inputs.json")?;
        let set = serde_json::from_reader(&mut file).unwrap_or_else(|_| OutPointSet::new());
        Ok(Self { set, file })
    }

    fn insert(&mut self, input: bitcoin::OutPoint) -> Result<bool> {
        use std::io::Write;

        let unseen = self.set.insert(input);
        let serialized = serde_json::to_string(&self.set)?;
        self.file.write_all(serialized.as_bytes())?;
        Ok(unseen)
    }
}
#[derive(Debug, Serialize, Deserialize)]
struct OutPointSet(HashSet<bitcoin::OutPoint>);

use std::fs::OpenOptions;
impl OutPointSet {
    fn new() -> Self { Self(HashSet::new()) }

    fn insert(&mut self, input: bitcoin::OutPoint) -> bool { self.0.insert(input) }
}

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
            .set_default("danger_accept_invalid_certs", false)?
            .set_default("pj_host", "0.0.0.0:3000")?
            .set_default("pj_endpoint", "https://localhost:3000")?
            .set_default("sub_only", false)?
            .add_source(File::new("config.toml", FileFormat::Toml));

        let builder = match matches.subcommand() {
            Some(("send", matches)) => builder.set_override_option(
                "danger_accept_invalid_certs",
                matches.get_one::<bool>("DANGER_ACCEPT_INVALID_CERTS").copied(),
            )?,
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
        app_conf.try_deserialize().context("Failed to deserialize config")
    }
}

fn try_contributing_inputs(
    payjoin: &mut PayjoinProposal,
    bitcoind: &bitcoincore_rpc::Client,
) -> Result<()> {
    use bitcoin::OutPoint;

    let available_inputs = bitcoind
        .list_unspent(None, None, None, None, None)
        .context("Failed to list unspent from bitcoind")?;
    let candidate_inputs: HashMap<Amount, OutPoint> = available_inputs
        .iter()
        .map(|i| (i.amount, OutPoint { txid: i.txid, vout: i.vout }))
        .collect();

    let selected_outpoint = payjoin.try_preserving_privacy(candidate_inputs).expect("gg");
    let selected_utxo = available_inputs
        .iter()
        .find(|i| i.txid == selected_outpoint.txid && i.vout == selected_outpoint.vout)
        .context("This shouldn't happen. Failed to retrieve the privacy preserving utxo from those we provided to the seclector.")?;
    log::debug!("selected utxo: {:#?}", selected_utxo);

    //  calculate receiver payjoin outputs given receiver payjoin inputs and original_psbt,
    let txo_to_contribute = bitcoin::TxOut {
        value: selected_utxo.amount.to_sat(),
        script_pubkey: selected_utxo.script_pub_key.clone(),
    };
    let outpoint_to_contribute =
        bitcoin::OutPoint { txid: selected_utxo.txid, vout: selected_utxo.vout };
    payjoin.contribute_witness_input(txo_to_contribute, outpoint_to_contribute);
    Ok(())
}

struct Headers<'a>(rouille::HeadersIter<'a>);
impl payjoin::receive::Headers for Headers<'_> {
    fn get_header(&self, key: &str) -> Option<&str> {
        let mut copy = self.0.clone(); // lol
        copy.find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v)
    }
}

fn serialize_psbt(psbt: &Psbt) -> String { base64::encode(&psbt.serialize()) }
