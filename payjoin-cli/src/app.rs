use std::borrow::Cow;
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
        let link = payjoin::Uri::try_from(bip21)
            .map_err(|e| anyhow!("Failed to create URI from BIP21: {}", e))?;

        let link = link
            .assume_checked()
            .check_pj_supported()
            .map_err(|e| anyhow!("The provided URI doesn't support payjoin (BIP78): {}", e))?;

        let amount = link
            .amount
            .ok_or_else(|| anyhow!("please specify the amount in the Uri"))
            .map(|amt| Amount::from_sat(amt.to_sat()))?;
        let mut outputs = HashMap::with_capacity(1);
        outputs.insert(link.address.to_string(), amount);

        let options = bitcoincore_rpc::json::WalletCreateFundedPsbtOptions {
            lock_unspent: Some(true),
            fee_rate: Some(Amount::from_sat(2000)),
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
        let pj_params = payjoin::send::Configuration::with_fee_contribution(
            payjoin::bitcoin::Amount::from_sat(10000),
            None,
        );
        let (req, ctx) = link
            .create_pj_request(psbt, pj_params)
            .with_context(|| "Failed to create payjoin request")?;
        log::debug!("Sending payjoin request body: {:#?}", req.body);
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

    #[cfg(not(feature = "reelay"))]
    pub fn receive_payjoin(self, amount_arg: &str) -> Result<()> {
        let amount = Amount::from_sat(amount_arg.parse()?);
        let pj_uri_string = self.make_pj_uri_string(amount)?;

        println!(
            "Listening at {}. Configured to accept payjoin at BIP 21 Payjoin Uri:",
            self.config.pj_host
        );
        println!("{}", pj_uri_string);

        rouille::start_server(self.config.pj_host.clone(), move |req| self.handle_web_request(req));
    }

    fn make_pj_uri_string(&self, amount: Amount) -> Result<String> {
        use payjoin::Uri;

        let address = self.bitcoind.get_new_address(None, None)?.assume_checked();
        let pj_uri_string = format!(
            "{}?amount={}&pj={}",
            address.to_qr_uri(),
            amount.to_btc(),
            self.config.pj_endpoint
        );
        let pj_uri = Uri::from_str(&pj_uri_string)
        .map_err(|e| anyhow!("Constructed a bad URI string from args: {}", e))?;
        let _pj_uri = pj_uri
            .assume_checked()
            .check_pj_supported()
            .map_err(|e| anyhow!("Constructed URI does not support payjoin: {}", e))?;
        Ok(pj_uri_string)
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
            ("POST", _) =>  {
                let headers = RouilleHeaders(req.headers());
                let body = req.data().context("Failed to read request body").map_err(|e| {
                    log::warn!("Failed to read request body: {}", e);
                    Error::Server(e.into())
                }).unwrap(); // return Response::text(e.to_string()).with_status_code(500)
                self
                    .handle_payjoin_post(body, req.raw_query_string(), headers)
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
                    .unwrap_or_else(|err_resp| err_resp)
            }
            _ => Response::empty_404(),
        }
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

    fn handle_payjoin_post(&self, body: impl std::io::Read, query: &str, headers: impl payjoin::receive::Headers) -> Result<Response, Error> {
        log::debug!("handle_payjoin_post");
        let proposal = payjoin::receive::UncheckedProposal::from_request(body, query, headers)?;
        
        // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
        let _to_broadcast_in_failure_case = proposal.get_transaction_to_schedule_broadcast();

        // The network is used for checks later
        let network = match self
            .bitcoind
            .get_blockchain_info()
            .map_err(|e| Error::Server(e.into()))?
            .chain
            .as_str()
        {
            "main" => bitcoin::Network::Bitcoin,
            "test" => bitcoin::Network::Testnet,
            "regtest" => bitcoin::Network::Regtest,
            _ => return Err(Error::Server(anyhow!("Unknown network").into())),
        };

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
            .set_default("pj_endpoint", "https://localhost:3010")?
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

struct RouilleHeaders<'a>(rouille::HeadersIter<'a>);
impl payjoin::receive::Headers for RouilleHeaders<'_> {
    fn get_header(&self, key: &str) -> Option<&str> {
        let mut copy = self.0.clone(); // lol
        copy.find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v)
    }
}

fn serialize_psbt(psbt: &Psbt) -> String { base64::encode(&psbt.serialize()) }

#[cfg(feature = "reelay")]
use tungstenite::{connect, Message};
#[cfg(feature = "reelay")]

use url::Url;
#[cfg(feature = "reelay")]
impl App {
    pub fn reeceive_payjoin(self, amount_arg: &str) -> Result<()> {
        use std::io::Read;
        use payjoin::relay;

        let amount = Amount::from_sat(amount_arg.parse()?);
        let pj_uri_string = self.make_pj_uri_string(amount)?;

        println!("{}", pj_uri_string);
        let ws_uri = "ws://localhost:3012/socket";
        println!(
            "Listening via relay at {}. Configured to accept payjoin at BIP 21 Payjoin Uri:",
            self.config.pj_host
        );
        println!("{}", pj_uri_string);

        // listen for incoming payjoin requests at ws
        println!("REElay");
        let (mut socket, response) =
            connect(Url::parse(ws_uri).unwrap()).expect("Can't connect");

        println!("Connected to the server");
        println!("Response HTTP code: {}", response.status());
        println!("Response contains the following headers:");
        for (ref header, _value) in response.headers() {
            println!("* {}", header);
        }
 
        socket.write_message(Message::Text("Hello WebSocket".into())).unwrap();
        println!("Waiting for messages...");
        let msg = socket.read_message().expect("Error reading message");
        println!("Received Request, deserializing: {}", msg);
        // for a production protocol bhttp would make more sense than json
        let req: relay::Request = serde_json::from_str(&msg.to_text().unwrap()).unwrap();
        println!("Deserialized request: {:?}", req);
        //let body = req.body
        println!("desrialized headers: {:?}", req.headers);
        let headers = HyperHeaders(req.headers);
        let body = std::io::Cursor::new(req.body);
        println!("deserialized body: {:?}", body);
        println!("Handling relayed payjoin POST request");
        // do receive
        let res = self.handle_payjoin_post(body, &req.query, headers)
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
            .unwrap_or_else(|err_resp| err_resp);
        println!("Serializing response");
        let (mut reader, _usize) = res.data.into_reader_and_size();
        let mut body = Vec::<u8>::new();
        reader.read_to_end(&mut body).unwrap();
        println!("read body into buffer");
        let headers = relay::VecHeaders::new(res.headers);
        let res =  relay::Response {
            body,
            headers,
            status_code: res.status_code,
        };
        let res = serde_json::to_string(&res).unwrap();
        println!("serialized res: {:#?}", res);
        socket.write_message(Message::Text(res)).unwrap();
        socket.close(None).unwrap();

        Ok(())
    }
}

#[cfg(feature = "reelay")]
#[derive(Debug)]
struct HyperHeaders(reqwest::header::HeaderMap);
#[cfg(feature = "reelay")]
impl payjoin::receive::Headers for HyperHeaders {
    fn get_header(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }
}