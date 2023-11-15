use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use bitcoincore_rpc::bitcoin::Amount;
use bitcoincore_rpc::jsonrpc::serde_json;
use bitcoincore_rpc::RpcApi;
use clap::ArgMatches;
use config::{Config, File, FileFormat};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use payjoin::bitcoin;
use payjoin::bitcoin::psbt::Psbt;
use payjoin::receive::{Error, ProvisionalProposal};
use serde::{Deserialize, Serialize};
use tokio::task::spawn_blocking;

#[cfg(feature = "danger-local-https")]
const LOCAL_CERT_FILE: &str = "localhost.der";

#[derive(Clone)]
pub(crate) struct App {
    config: AppConfig,
    seen_inputs: Arc<Mutex<SeenInputs>>,
}

impl App {
    pub fn new(config: AppConfig) -> Result<Self> {
        let seen_inputs = Arc::new(Mutex::new(SeenInputs::new()?));
        Ok(Self { config, seen_inputs })
    }

    pub fn bitcoind(&self) -> Result<bitcoincore_rpc::Client> {
        match &self.config.bitcoind_cookie {
            Some(cookie) => bitcoincore_rpc::Client::new(
                &self.config.bitcoind_rpchost,
                bitcoincore_rpc::Auth::CookieFile(cookie.into()),
            ),
            None => bitcoincore_rpc::Client::new(
                &self.config.bitcoind_rpchost,
                bitcoincore_rpc::Auth::UserPass(
                    self.config.bitcoind_rpcuser.clone(),
                    self.config.bitcoind_rpcpass.clone(),
                ),
            ),
        }
        .with_context(|| "Failed to connect to bitcoind")
    }

    pub async fn send_payjoin(&self, bip21: &str, fee_rate: &f32) -> Result<()> {
        let uri = payjoin::Uri::try_from(bip21)
            .map_err(|e| anyhow!("Failed to create URI from BIP21: {}", e))?
            .assume_checked();

        let amount = uri.amount.ok_or_else(|| anyhow!("please specify the amount in the Uri"))?;

        // wallet_create_funded_psbt requires a HashMap<address: String, Amount>
        let mut outputs = HashMap::with_capacity(1);
        outputs.insert(uri.address.to_string(), amount);
        let fee_rate_sat_per_kwu = fee_rate * 250.0_f32;
        let fee_rate: bitcoin::FeeRate =
            bitcoin::FeeRate::from_sat_per_kwu(fee_rate_sat_per_kwu.ceil() as u64);
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
            .bitcoind()?
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
            .bitcoind()?
            .wallet_process_psbt(&psbt, None, None, None)
            .with_context(|| "Failed to process PSBT")?
            .psbt;
        let psbt = Psbt::from_str(&psbt).with_context(|| "Failed to load PSBT from base64")?;
        log::debug!("Original psbt: {:#?}", psbt);
        let fallback_tx = psbt.clone().extract_tx();
        let (req, ctx) = payjoin::send::RequestBuilder::from_psbt_and_uri(psbt, uri)
            .with_context(|| "Failed to build payjoin request")?
            .build_recommended(fee_rate)
            .with_context(|| "Failed to build payjoin request")?
            .extract_v1()?;

        let http = http_agent()?;
        println!("Sending fallback request to {}", &req.url);
        let response = spawn_blocking(move || {
            http.post(req.url.as_str())
                .set("Content-Type", "text/plain")
                .send_bytes(&req.body)
                .with_context(|| "HTTP request failed")
        })
        .await??;
        println!("Sent fallback transaction txid: {}", fallback_tx.txid());
        println!(
            "Sent fallback transaction hex: {:#}",
            payjoin::bitcoin::consensus::encode::serialize_hex(&fallback_tx)
        );
        // TODO display well-known errors and log::debug the rest
        let psbt = ctx
            .process_response(&mut response.into_reader())
            .with_context(|| "Failed to process response")?;
        log::debug!("Proposed psbt: {:#?}", psbt);
        let psbt = self
            .bitcoind()?
            .wallet_process_psbt(&serialize_psbt(&psbt), None, None, None)
            .with_context(|| "Failed to process PSBT")?
            .psbt;
        let tx = self
            .bitcoind()?
            .finalize_psbt(&psbt, Some(true))
            .with_context(|| "Failed to finalize PSBT")?
            .hex
            .ok_or_else(|| anyhow!("Incomplete PSBT"))?;
        let txid = self
            .bitcoind()?
            .send_raw_transaction(&tx)
            .with_context(|| "Failed to send raw transaction")?;
        println!("Payjoin sent: {}", txid);
        Ok(())
    }

    pub async fn receive_payjoin(self, amount_arg: &str) -> Result<()> {
        use payjoin::Uri;

        let pj_receiver_address = self.bitcoind()?.get_new_address(None, None)?.assume_checked();
        let amount = Amount::from_sat(amount_arg.parse()?);
        let pj_uri_string = format!(
            "{}?amount={}&pj={}",
            pj_receiver_address.to_qr_uri(),
            amount.to_btc(),
            self.config.pj_endpoint
        );
        // check that the URI is corrctly formatted
        let _pj_uri = Uri::from_str(&pj_uri_string)
            .map_err(|e| anyhow!("Constructed a bad URI string from args: {}", e))?
            .assume_checked();
        let bind_addr: SocketAddr = self.config.pj_host.parse()?;
        println!(
            "Listening at {}. Configured to accept payjoin at BIP 21 Payjoin Uri:",
            self.config.pj_host
        );
        println!("{}", pj_uri_string);

        #[cfg(feature = "danger-local-https")]
        let server = {
            use std::io::Write;

            use hyper::server::conn::AddrIncoming;
            use rustls::{Certificate, PrivateKey};

            let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
            let cert_der = cert.serialize_der()?;
            let mut local_cert_path = std::env::temp_dir();
            local_cert_path.push(LOCAL_CERT_FILE);
            let mut file = std::fs::File::create(local_cert_path)?;
            file.write_all(&cert_der)?;
            let key = PrivateKey(cert.serialize_private_key_der());
            let certs = vec![Certificate(cert.serialize_der()?)];
            let incoming = AddrIncoming::bind(&bind_addr.into())?;
            let acceptor = hyper_rustls::TlsAcceptor::builder()
                .with_single_cert(certs, key)
                .map_err(|e| anyhow::anyhow!("TLS error: {}", e))?
                .with_all_versions_alpn()
                .with_incoming(incoming);
            Server::builder(acceptor)
        };

        #[cfg(not(feature = "danger-local-https"))]
        let server = Server::bind(&bind_addr);

        let make_svc = make_service_fn(|_| {
            let app = self.clone();
            async move {
                let handler = move |req| app.clone().handle_web_request(req);
                Ok::<_, hyper::Error>(service_fn(handler))
            }
        });
        server.serve(make_svc).await?;
        Ok(())
    }

    async fn handle_web_request(self, req: Request<Body>) -> Result<Response<Body>> {
        log::debug!("Received request: {:?}", req);
        let mut response = match (req.method(), req.uri().path()) {
            (&Method::GET, "/bip21") => {
                let query_string = req.uri().query().unwrap_or("");
                log::debug!("{:?}, {:?}", req.method(), query_string);
                let query_params: HashMap<_, _> =
                    url::form_urlencoded::parse(query_string.as_bytes()).into_owned().collect();
                let amount = query_params.get("amount").map(|amt| {
                    Amount::from_btc(amt.parse().expect("Failed to parse amount")).unwrap()
                });
                self.handle_get_bip21(amount)
                    .map_err(|e| {
                        log::error!("Error handling request: {}", e);
                        Response::builder().status(500).body(Body::from(e.to_string())).unwrap()
                    })
                    .unwrap_or_else(|err_resp| err_resp)
            }
            (&Method::POST, _) => self
                .handle_payjoin_post(req)
                .await
                .map_err(|e| match e {
                    Error::BadRequest(e) => {
                        log::error!("Error handling request: {}", e);
                        Response::builder().status(400).body(Body::from(e.to_string())).unwrap()
                    }
                    e => {
                        log::error!("Error handling request: {}", e);
                        Response::builder().status(500).body(Body::from(e.to_string())).unwrap()
                    }
                })
                .unwrap_or_else(|err_resp| err_resp),
            _ => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("Not found"))
                .unwrap(),
        };
        response
            .headers_mut()
            .insert("Access-Control-Allow-Origin", hyper::header::HeaderValue::from_static("*"));
        Ok(response)
    }

    fn handle_get_bip21(&self, amount: Option<Amount>) -> Result<Response<Body>, Error> {
        let address = self
            .bitcoind()
            .map_err(|e| Error::Server(e.into()))?
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
        let _ = uri.assume_checked(); // we just got it from bitcoind above

        Ok(Response::new(Body::from(uri_string)))
    }

    async fn handle_payjoin_post(&self, req: Request<Body>) -> Result<Response<Body>, Error> {
        let (parts, body) = req.into_parts();
        let headers = Headers(&parts.headers);
        let query_string = parts.uri.query().unwrap_or("");
        let body = std::io::Cursor::new(
            hyper::body::to_bytes(body).await.map_err(|e| Error::Server(e.into()))?.to_vec(),
        );
        let proposal =
            payjoin::receive::UncheckedProposal::from_request(body, query_string, headers)?;

        let bitcoind = self.bitcoind().map_err(|e| Error::Server(e.into()))?;

        // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
        let _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast();

        // The network is used for checks later
        let network =
            bitcoind.get_blockchain_info().map_err(|e| Error::Server(e.into())).and_then(
                |info| bitcoin::Network::from_str(&info.chain).map_err(|e| Error::Server(e.into())),
            )?;

        // Receive Check 1: Can Broadcast
        let proposal = proposal.check_can_broadcast(|tx| {
            let raw_tx = bitcoin::consensus::encode::serialize_hex(&tx);
            let mempool_results =
                bitcoind.test_mempool_accept(&[raw_tx]).map_err(|e| Error::Server(e.into()))?;
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
                bitcoind
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

        let mut provisional_payjoin = payjoin.identify_receiver_outputs(|output_script| {
            if let Ok(address) = bitcoin::Address::from_script(output_script, network) {
                bitcoind
                    .get_address_info(&address)
                    .map(|info| info.is_mine.unwrap_or(false))
                    .map_err(|e| Error::Server(e.into()))
            } else {
                Ok(false)
            }
        })?;

        if !self.config.sub_only {
            // Select receiver payjoin inputs.
            _ = try_contributing_inputs(&mut provisional_payjoin, &bitcoind)
                .map_err(|e| log::warn!("Failed to contribute inputs: {}", e));
        }

        let receiver_substitute_address = bitcoind
            .get_new_address(None, None)
            .map_err(|e| Error::Server(e.into()))?
            .assume_checked();
        provisional_payjoin.substitute_output_address(receiver_substitute_address);

        let payjoi_proposal = provisional_payjoin.finalize_proposal(
            |psbt: &Psbt| {
                bitcoind
                    .wallet_process_psbt(
                        &payjoin::base64::encode(psbt.serialize()),
                        None,
                        None,
                        Some(false),
                    )
                    .map(|res| Psbt::from_str(&res.psbt).map_err(|e| Error::Server(e.into())))
                    .map_err(|e| Error::Server(e.into()))?
            },
            Some(bitcoin::FeeRate::MIN),
        )?;
        let payjoin_proposal_psbt = payjoi_proposal.psbt();
        log::debug!("Receiver's Payjoin proposal PSBT Rsponse: {:#?}", payjoin_proposal_psbt);

        let payload = payjoin::base64::encode(payjoin_proposal_psbt.serialize());
        log::info!("successful response");
        Ok(Response::new(Body::from(payload)))
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

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AppConfig {
    pub bitcoind_rpchost: String,
    pub bitcoind_cookie: Option<String>,
    pub bitcoind_rpcuser: String,
    pub bitcoind_rpcpass: String,

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
        app_conf.try_deserialize().context("Failed to deserialize config")
    }
}

fn try_contributing_inputs(
    payjoin: &mut ProvisionalProposal,
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

struct Headers<'a>(&'a hyper::HeaderMap);
impl payjoin::receive::Headers for Headers<'_> {
    fn get_header(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(|v| v.to_str()).transpose().ok().flatten()
    }
}

fn serialize_psbt(psbt: &Psbt) -> String { payjoin::base64::encode(&psbt.serialize()) }

#[cfg(feature = "danger-local-https")]
fn http_agent() -> Result<ureq::Agent> {
    use rustls::client::ClientConfig;
    use rustls::{Certificate, RootCertStore};
    use ureq::AgentBuilder;

    let mut local_cert_path = std::env::temp_dir();
    local_cert_path.push(LOCAL_CERT_FILE);
    let cert_der = std::fs::read(local_cert_path)?;
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.add(&Certificate(cert_der))?;
    let client_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    Ok(AgentBuilder::new().tls_config(Arc::new(client_config)).build())
}

#[cfg(not(feature = "danger-local-https"))]
fn http_agent() -> Result<ureq::Agent> { Ok(ureq::Agent::new()) }
