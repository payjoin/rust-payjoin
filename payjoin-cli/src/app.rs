use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
#[cfg(not(feature = "v2"))]
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use bitcoincore_rpc::bitcoin::Amount;
use bitcoincore_rpc::jsonrpc::serde_json;
use bitcoincore_rpc::RpcApi;
use clap::ArgMatches;
use config::{Config, File, FileFormat};
#[cfg(not(feature = "v2"))]
use hyper::service::{make_service_fn, service_fn};
#[cfg(not(feature = "v2"))]
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::{self, base64};
#[cfg(feature = "v2")]
use payjoin::receive::v2;
use payjoin::receive::Error;
#[cfg(not(feature = "v2"))]
use payjoin::receive::{PayjoinProposal, UncheckedProposal};
use payjoin::send::RequestContext;
use serde::{Deserialize, Serialize};
#[cfg(feature = "v2")]
use tokio::sync::Mutex as AsyncMutex;
#[cfg(feature = "v2")]
use tokio::task::spawn_blocking;

#[cfg(feature = "danger-local-https")]
const LOCAL_CERT_FILE: &str = "localhost.der";

#[derive(Clone)]
pub(crate) struct App {
    config: AppConfig,
    #[cfg(feature = "v2")]
    receive_store: Arc<AsyncMutex<ReceiveStore>>,
    #[cfg(feature = "v2")]
    send_store: Arc<AsyncMutex<SendStore>>,
    seen_inputs: Arc<Mutex<SeenInputs>>,
}

impl App {
    pub fn new(config: AppConfig) -> Result<Self> {
        let seen_inputs = Arc::new(Mutex::new(SeenInputs::new()?));
        #[cfg(feature = "v2")]
        let receive_store = Arc::new(AsyncMutex::new(ReceiveStore::new()?));
        #[cfg(feature = "v2")]
        let send_store = Arc::new(AsyncMutex::new(SendStore::new()?));
        #[cfg(feature = "v2")]
        let app = Self { config, receive_store, send_store, seen_inputs };
        #[cfg(not(feature = "v2"))]
        let app = Self { config, seen_inputs };
        Ok(app)
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

    #[cfg(feature = "v2")]
    pub async fn send_payjoin(&self, bip21: &str, fee_rate: &f32, is_retry: bool) -> Result<()> {
        let mut session = self.send_store.lock().await;
        let req_ctx = if is_retry {
            log::debug!("Resuming session");
            // Get a reference to RequestContext
            session.req_ctx.as_mut().expect("RequestContext is missing")
        } else {
            let req_ctx = self.create_pj_request(bip21, fee_rate)?;
            session.write(req_ctx)?;
            log::debug!("Writing req_ctx");
            session.req_ctx.as_mut().expect("RequestContext is missing")
        };
        log::debug!("Awaiting response");
        let res = self.long_poll_post(req_ctx).await?;
        self.process_pj_response(res)?;
        session.clear()?;
        Ok(())
    }

    #[cfg(not(feature = "v2"))]
    pub async fn send_payjoin(&self, bip21: &str, fee_rate: &f32) -> Result<()> {
        let (req, ctx) = self.create_pj_request(bip21, fee_rate)?.extract_v1()?;
        let http = http_agent()?;
        let body = String::from_utf8(req.body.clone()).unwrap();
        println!("Sending fallback request to {}", &req.url);
        let response = http
            .post(req.url.as_str())
            .set("Content-Type", "text/plain")
            .send_string(&body.clone())
            .with_context(|| "HTTP request failed")?;
        let fallback_tx = Psbt::from_str(&body)
            .map_err(|e| anyhow!("Failed to load PSBT from base64: {}", e))?
            .extract_tx();
        println!("Sent fallback transaction txid: {}", fallback_tx.txid());
        println!(
            "Sent fallback transaction hex: {:#}",
            payjoin::bitcoin::consensus::encode::serialize_hex(&fallback_tx)
        );
        let psbt = ctx.process_response(&mut response.into_reader()).map_err(|e| {
            log::debug!("Error processing response: {:?}", e);
            anyhow!("Failed to process response {}", e)
        })?;

        self.process_pj_response(psbt)?;
        Ok(())
    }

    #[cfg(feature = "v2")]
    pub async fn receive_payjoin(self, amount_arg: &str, is_retry: bool) -> Result<()> {
        use v2::Enroller;

        let mut enrolled = if !is_retry {
            let mut enroller = Enroller::from_relay_config(
                &self.config.pj_endpoint,
                &self.config.ohttp_config,
                &self.config.ohttp_proxy,
            );
            let (req, ctx) = enroller.extract_req()?;
            log::debug!("Enrolling receiver");
            let http = http_agent()?;
            let ohttp_response = spawn_blocking(move || {
                http.post(req.url.as_ref()).send_bytes(&req.body).map_err(map_ureq_err)
            })
            .await??;

            let enrolled = enroller
                .process_res(ohttp_response.into_reader(), ctx)
                .map_err(|_| anyhow!("Enrollment failed"))?;
            self.receive_store.lock().await.write(enrolled.clone())?;
            enrolled
        } else {
            let session = self.receive_store.lock().await;
            log::debug!("Resuming session");
            session.session.clone().ok_or(anyhow!("No session found"))?
        };

        log::debug!("Enrolled receiver");

        let pj_uri_string =
            self.construct_payjoin_uri(amount_arg, Some(&enrolled.fallback_target()))?;
        println!(
            "Listening at {}. Configured to accept payjoin at BIP 21 Payjoin Uri:",
            self.config.pj_host
        );
        println!("{}", pj_uri_string);

        log::debug!("Awaiting proposal");
        let res = self.long_poll_fallback(&mut enrolled).await?;
        log::debug!("Received request");
        let mut payjoin_proposal = self
            .process_v2_proposal(res)
            .map_err(|e| anyhow!("Failed to process proposal {}", e))?;
        log::debug!("Posting payjoin back");
        let (req, ohttp_ctx) = payjoin_proposal
            .extract_v2_req()
            .map_err(|e| anyhow!("v2 req extraction failed {}", e))?;
        let http = http_agent()?;
        let res = http.post(req.url.as_str()).send_bytes(&req.body).map_err(map_ureq_err)?;
        let mut buf = Vec::new();
        let _ = res.into_reader().read_to_end(&mut buf)?;
        let res = payjoin_proposal.deserialize_res(buf, ohttp_ctx);
        log::debug!("Received response {:?}", res);
        self.receive_store.lock().await.clear()?;
        Ok(())
    }

    #[cfg(not(feature = "v2"))]
    pub async fn receive_payjoin(self, amount_arg: &str) -> Result<()> {
        let pj_uri_string = self.construct_payjoin_uri(amount_arg, None)?;
        println!(
            "Listening at {}. Configured to accept payjoin at BIP 21 Payjoin Uri:",
            self.config.pj_host
        );
        println!("{}", pj_uri_string);

        self.start_http_server().await?;
        Ok(())
    }

    #[cfg(feature = "v2")]
    async fn long_poll_post(&self, req_ctx: &mut payjoin::send::RequestContext) -> Result<Psbt> {
        loop {
            let (req, ctx) = req_ctx.extract_v2(&self.config.ohttp_proxy)?;
            println!("Sending fallback request to {}", &req.url);
            let http = http_agent()?;
            let response = spawn_blocking(move || {
                http.post(req.url.as_ref())
                    .set("Content-Type", "text/plain")
                    .send_bytes(&req.body)
                    .map_err(map_ureq_err)
            })
            .await??;

            println!("Sent fallback transaction");
            match ctx.process_response(&mut response.into_reader()) {
                Ok(Some(psbt)) => return Ok(psbt),
                Ok(None) => std::thread::sleep(std::time::Duration::from_secs(5)),
                Err(re) => {
                    println!("{}", re);
                    log::debug!("{:?}", re);
                }
            }
        }
    }

    #[cfg(feature = "v2")]
    async fn long_poll_fallback(
        &self,
        enrolled: &mut payjoin::receive::v2::Enrolled,
    ) -> Result<payjoin::receive::v2::UncheckedProposal> {
        loop {
            let (req, context) =
                enrolled.extract_req().map_err(|_| anyhow!("Failed to extract request"))?;
            log::debug!("GET fallback_psbt");
            let http = http_agent()?;
            let ohttp_response = spawn_blocking(move || {
                http.post(req.url.as_str()).send_bytes(&req.body).map_err(map_ureq_err)
            })
            .await??;

            let proposal = enrolled
                .process_res(ohttp_response.into_reader(), context)
                .map_err(|_| anyhow!("GET fallback failed"))?;
            log::debug!("got response");
            match proposal {
                Some(proposal) => break Ok(proposal),
                None => std::thread::sleep(std::time::Duration::from_secs(5)),
            }
        }
    }

    fn create_pj_request(&self, bip21: &str, fee_rate: &f32) -> Result<RequestContext> {
        let uri = payjoin::Uri::try_from(bip21)
            .map_err(|e| anyhow!("Failed to create URI from BIP21: {}", e))?;

        let uri = uri.assume_checked();

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
        let req_ctx = payjoin::send::RequestBuilder::from_psbt_and_uri(psbt, uri)
            .with_context(|| "Failed to build payjoin request")?
            .build_recommended(fee_rate)
            .with_context(|| "Failed to build payjoin request")?;

        Ok(req_ctx)
    }

    fn process_pj_response(&self, psbt: Psbt) -> Result<bitcoin::Txid> {
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
        Ok(txid)
    }

    #[cfg(not(feature = "v2"))]
    async fn start_http_server(self) -> Result<()> {
        let bind_addr: SocketAddr = self.config.pj_host.parse()?;

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
        let app = self.clone();
        let make_svc = make_service_fn(|_| {
            let app = app.clone();
            async move {
                let handler = move |req| app.clone().handle_web_request(req);
                Ok::<_, hyper::Error>(service_fn(handler))
            }
        });
        server.serve(make_svc).await?;
        Ok(())
    }

    fn construct_payjoin_uri(
        &self,
        amount_arg: &str,
        fallback_target: Option<&str>,
    ) -> Result<String> {
        let pj_receiver_address = self.bitcoind()?.get_new_address(None, None)?.assume_checked();
        let amount = Amount::from_sat(amount_arg.parse()?);
        let pj_part = match fallback_target {
            Some(target) => target,
            None => self.config.pj_endpoint.as_str(),
        };

        let pj_uri_string = format!(
            "{}?amount={}&pj={}",
            pj_receiver_address.to_qr_uri(),
            amount.to_btc(),
            pj_part,
        );

        #[cfg(feature = "v2")]
        let pj_uri_string = format!("{}&ohttp={}", pj_uri_string, self.config.ohttp_config,);

        // to check uri validity
        let _pj_uri = payjoin::Uri::from_str(&pj_uri_string)
            .map_err(|e| anyhow!("Constructed a bad URI string from args: {}", e))?;

        Ok(pj_uri_string)
    }

    #[cfg(not(feature = "v2"))]
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

    #[cfg(not(feature = "v2"))]
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

    #[cfg(not(feature = "v2"))]
    async fn handle_payjoin_post(&self, req: Request<Body>) -> Result<Response<Body>, Error> {
        let (parts, body) = req.into_parts();
        let headers = Headers(&parts.headers);
        let query_string = parts.uri.query().unwrap_or("");
        let body = std::io::Cursor::new(
            hyper::body::to_bytes(body).await.map_err(|e| Error::Server(e.into()))?.to_vec(),
        );
        let proposal =
            payjoin::receive::UncheckedProposal::from_request(body, query_string, headers)?;

        let payjoin_proposal = self.process_v1_proposal(proposal)?;
        let psbt = payjoin_proposal.psbt();
        let body = base64::encode(psbt.serialize());
        println!("Responded with Payjoin proposal {}", psbt.clone().extract_tx().txid());
        Ok(Response::new(Body::from(body)))
    }

    #[cfg(not(feature = "v2"))]
    fn process_v1_proposal(&self, proposal: UncheckedProposal) -> Result<PayjoinProposal, Error> {
        let bitcoind = self.bitcoind().map_err(|e| Error::Server(e.into()))?;

        // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
        let _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast();

        // The network is used for checks later
        let network =
            bitcoind.get_blockchain_info().map_err(|e| Error::Server(e.into())).and_then(
                |info| bitcoin::Network::from_str(&info.chain).map_err(|e| Error::Server(e.into())),
            )?;

        // Receive Check 1: Can Broadcast
        let proposal = proposal.check_broadcast_suitability(None, |tx| {
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

        let payjoin_proposal = provisional_payjoin.finalize_proposal(
            |psbt: &Psbt| {
                bitcoind
                    .wallet_process_psbt(&base64::encode(psbt.serialize()), None, None, Some(false))
                    .map(|res| Psbt::from_str(&res.psbt).map_err(|e| Error::Server(e.into())))
                    .map_err(|e| Error::Server(e.into()))?
            },
            Some(bitcoin::FeeRate::MIN),
        )?;
        let payjoin_proposal_psbt = payjoin_proposal.psbt();
        println!(
            "Responded with Payjoin proposal {}",
            payjoin_proposal_psbt.clone().extract_tx().txid()
        );
        Ok(payjoin_proposal)
    }

    #[cfg(feature = "v2")]
    fn process_v2_proposal(
        &self,
        proposal: v2::UncheckedProposal,
    ) -> Result<v2::PayjoinProposal, Error> {
        let bitcoind = self.bitcoind().map_err(|e| Error::Server(e.into()))?;

        // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
        let _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast();

        // The network is used for checks later
        let network =
            bitcoind.get_blockchain_info().map_err(|e| Error::Server(e.into())).and_then(
                |info| bitcoin::Network::from_str(&info.chain).map_err(|e| Error::Server(e.into())),
            )?;

        // Receive Check 1: Can Broadcast
        let proposal = proposal.check_broadcast_suitability(None, |tx| {
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
            _ = try_contributing_inputs(&mut provisional_payjoin.inner, &bitcoind)
                .map_err(|e| log::warn!("Failed to contribute inputs: {}", e));
        }

        let receiver_substitute_address = bitcoind
            .get_new_address(None, None)
            .map_err(|e| Error::Server(e.into()))?
            .assume_checked();
        provisional_payjoin.substitute_output_address(receiver_substitute_address);

        let payjoin_proposal = provisional_payjoin.finalize_proposal(
            |psbt: &Psbt| {
                bitcoind
                    .wallet_process_psbt(&base64::encode(psbt.serialize()), None, None, Some(false))
                    .map(|res| Psbt::from_str(&res.psbt).map_err(|e| Error::Server(e.into())))
                    .map_err(|e| Error::Server(e.into()))?
            },
            Some(bitcoin::FeeRate::MIN),
        )?;
        let payjoin_proposal_psbt = payjoin_proposal.psbt();
        log::debug!("Receiver's Payjoin proposal PSBT Rsponse: {:#?}", payjoin_proposal_psbt);
        Ok(payjoin_proposal)
    }

    fn insert_input_seen_before(&self, input: bitcoin::OutPoint) -> Result<bool> {
        self.seen_inputs.lock().expect("mutex lock failed").insert(input)
    }
}

#[cfg(feature = "v2")]
struct SendStore {
    req_ctx: Option<payjoin::send::RequestContext>,
    file: std::fs::File,
}

#[cfg(feature = "v2")]
impl SendStore {
    fn new() -> Result<Self> {
        let mut file =
            OpenOptions::new().write(true).read(true).create(true).open("send_store.json")?;
        let session = match serde_json::from_reader(&mut file) {
            Ok(session) => Some(session),
            Err(e) => {
                log::debug!("error reading send session store: {}", e);
                None
            }
        };

        Ok(Self { req_ctx: session, file })
    }

    fn write(
        &mut self,
        session: payjoin::send::RequestContext,
    ) -> Result<&mut payjoin::send::RequestContext> {
        use std::io::Write;

        let session = self.req_ctx.insert(session);
        let serialized = serde_json::to_string(session)?;
        self.file.write_all(serialized.as_bytes())?;
        Ok(session)
    }

    fn clear(&mut self) -> Result<()> {
        let file = OpenOptions::new().write(true).open("send_store.json")?;
        file.set_len(0)?;
        Ok(())
    }
}

#[cfg(feature = "v2")]
struct ReceiveStore {
    session: Option<payjoin::receive::v2::Enrolled>,
    file: std::fs::File,
}

#[cfg(feature = "v2")]
impl ReceiveStore {
    fn new() -> Result<Self> {
        let mut file =
            OpenOptions::new().write(true).read(true).create(true).open("receive_store.json")?;
        let session = match serde_json::from_reader(&mut file) {
            Ok(session) => Some(session),
            Err(e) => {
                log::debug!("error reading receive session store: {}", e);
                None
            }
        };

        Ok(Self { session, file })
    }

    fn write(
        &mut self,
        session: payjoin::receive::v2::Enrolled,
    ) -> Result<&mut payjoin::receive::v2::Enrolled> {
        use std::io::Write;

        let session = self.session.insert(session);
        let serialized = serde_json::to_string(session)?;
        self.file.write_all(serialized.as_bytes())?;
        Ok(session)
    }

    fn clear(&mut self) -> Result<()> {
        let file = OpenOptions::new().write(true).open("receive_store.json")?;
        file.set_len(0)?;
        Ok(())
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

fn try_contributing_inputs(
    payjoin: &mut payjoin::receive::ProvisionalProposal,
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

fn serialize_psbt(psbt: &Psbt) -> String { base64::encode(psbt.serialize()) }

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

#[cfg(feature = "v2")]
fn map_ureq_err(e: ureq::Error) -> anyhow::Error {
    let e_string = e.to_string();
    match e.into_response() {
        Some(res) => anyhow!(
            "HTTP request failed: {} {}",
            res.status(),
            res.into_string().unwrap_or_default()
        ),
        None => anyhow!("No HTTP response: {}", e_string),
    }
}
