use std::fs::OpenOptions;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use bitcoincore_rpc::jsonrpc::serde_json;
use bitcoincore_rpc::RpcApi;
use payjoin::bitcoin::consensus::encode::serialize_hex;
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::Amount;
use payjoin::{base64, bitcoin, Error, PjUriBuilder};
use tokio::sync::Mutex as AsyncMutex;

use super::config::AppConfig;
use super::{App as AppTrait, SeenInputs};
use crate::app::http_agent;

#[derive(Clone)]
pub(crate) struct App {
    config: AppConfig,
    receive_store: Arc<AsyncMutex<ReceiveStore>>,
    send_store: Arc<AsyncMutex<SendStore>>,
    seen_inputs: Arc<Mutex<SeenInputs>>,
}

#[async_trait::async_trait]
impl AppTrait for App {
    fn new(config: AppConfig) -> Result<Self> {
        let seen_inputs = Arc::new(Mutex::new(SeenInputs::new()?));
        let receive_store = Arc::new(AsyncMutex::new(ReceiveStore::new()?));
        let send_store = Arc::new(AsyncMutex::new(SendStore::new()?));
        let app = Self { config, receive_store, send_store, seen_inputs };
        app.bitcoind()?
            .get_blockchain_info()
            .context("Failed to connect to bitcoind. Check config RPC connection.")?;
        Ok(app)
    }

    fn bitcoind(&self) -> Result<bitcoincore_rpc::Client> {
        match &self.config.bitcoind_cookie {
            Some(cookie) => bitcoincore_rpc::Client::new(
                self.config.bitcoind_rpchost.as_str(),
                bitcoincore_rpc::Auth::CookieFile(cookie.into()),
            ),
            None => bitcoincore_rpc::Client::new(
                self.config.bitcoind_rpchost.as_str(),
                bitcoincore_rpc::Auth::UserPass(
                    self.config.bitcoind_rpcuser.clone(),
                    self.config.bitcoind_rpcpassword.clone(),
                ),
            ),
        }
        .with_context(|| "Failed to connect to bitcoind")
    }

    async fn send_payjoin(&self, bip21: &str, fee_rate: &f32, is_retry: bool) -> Result<()> {
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

    async fn receive_payjoin(self, amount_arg: &str, is_retry: bool) -> Result<()> {
        use payjoin::receive::v2::Enroller;

        let ohttp_keys = unwrap_ohttp_keys_or_else_fetch(&self.config).await?;
        let mut enrolled = if !is_retry {
            let mut enroller = Enroller::from_directory_config(
                self.config.pj_directory.clone(),
                ohttp_keys.clone(),
                self.config.ohttp_relay.clone(),
            );
            let (req, ctx) =
                enroller.extract_req().map_err(|e| anyhow!("Failed to extract request {}", e))?;
            println!("Starting new Payjoin session with {}", self.config.pj_directory);
            let http = http_agent()?;
            let ohttp_response = http
                .post(req.url)
                .header("Content-Type", payjoin::V2_REQ_CONTENT_TYPE)
                .body(req.body)
                .send()
                .await
                .map_err(map_reqwest_err)?;

            let enrolled = enroller
                .process_res(ohttp_response.bytes().await?.to_vec().as_slice(), ctx)
                .map_err(|_| anyhow!("Enrollment failed"))?;
            self.receive_store.lock().await.write(enrolled.clone())?;
            enrolled
        } else {
            let session = self.receive_store.lock().await;
            println!("Resuming Payjoin session"); // TODO include session pubkey / payjoin directory
            session.session.clone().ok_or(anyhow!("No session found"))?
        };

        println!("Receive session established");
        let pj_uri_string =
            self.construct_payjoin_uri(amount_arg, &enrolled.fallback_target(), ohttp_keys)?;
        println!("Request Payjoin by sharing this Payjoin Uri:");
        println!("{}", pj_uri_string);

        let res = self.long_poll_fallback(&mut enrolled).await?;
        println!("Fallback transaction received. Consider broadcasting this to get paid if the Payjoin fails:");
        println!("{}", serialize_hex(&res.extract_tx_to_schedule_broadcast()));
        let mut payjoin_proposal = self
            .process_v2_proposal(res)
            .map_err(|e| anyhow!("Failed to process proposal {}", e))?;
        let (req, ohttp_ctx) = payjoin_proposal
            .extract_v2_req()
            .map_err(|e| anyhow!("v2 req extraction failed {}", e))?;
        println!("Got a request from the sender. Responding with a Payjoin proposal.");
        let http = http_agent()?;
        let res = http
            .post(req.url)
            .header("Content-Type", payjoin::V2_REQ_CONTENT_TYPE)
            .body(req.body)
            .send()
            .await
            .map_err(map_reqwest_err)?;
        let _res = payjoin_proposal
            .deserialize_res(res.bytes().await?.to_vec(), ohttp_ctx)
            .map_err(|e| anyhow!("Failed to deserialize response {}", e))?;
        let payjoin_psbt = payjoin_proposal.psbt().clone();
        println!(
            "Response successful. Watch mempool for successful Payjoin. TXID: {}",
            payjoin_psbt.extract_tx().clone().txid()
        );
        self.receive_store.lock().await.clear()?;
        Ok(())
    }
}

impl App {
    fn construct_payjoin_uri(
        &self,
        amount_arg: &str,
        fallback_target: &str,
        ohttp_keys: payjoin::OhttpKeys,
    ) -> Result<String> {
        let pj_receiver_address = self.bitcoind()?.get_new_address(None, None)?.assume_checked();
        let amount = Amount::from_sat(amount_arg.parse()?);
        let pj_part = payjoin::Url::parse(fallback_target)
            .map_err(|e| anyhow!("Failed to parse Payjoin subdirectory target: {}", e))?;

        let pj_uri = PjUriBuilder::new(pj_receiver_address, pj_part, Some(ohttp_keys))
            .amount(amount)
            .build();

        Ok(pj_uri.to_string())
    }

    async fn long_poll_post(&self, req_ctx: &mut payjoin::send::RequestContext) -> Result<Psbt> {
        loop {
            let (req, ctx) = req_ctx.extract_v2(self.config.ohttp_relay.clone())?;
            println!("Polling send request...");
            let http = http_agent()?;
            let response = http
                .post(req.url)
                .header("Content-Type", payjoin::V2_REQ_CONTENT_TYPE)
                .body(req.body)
                .send()
                .await
                .map_err(map_reqwest_err)?;

            println!("Sent fallback transaction");
            match ctx.process_response(&mut response.bytes().await?.to_vec().as_slice()) {
                Ok(Some(psbt)) => return Ok(psbt),
                Ok(None) => {
                    println!("No response yet.");
                    std::thread::sleep(std::time::Duration::from_secs(5))
                }
                Err(re) => {
                    println!("{}", re);
                    log::debug!("{:?}", re);
                    return Err(anyhow!("Response error").context(re));
                }
            }
        }
    }

    async fn long_poll_fallback(
        &self,
        enrolled: &mut payjoin::receive::v2::Enrolled,
    ) -> Result<payjoin::receive::v2::UncheckedProposal> {
        loop {
            let (req, context) =
                enrolled.extract_req().map_err(|_| anyhow!("Failed to extract request"))?;
            println!("Polling receive request...");
            let http = http_agent()?;
            let ohttp_response = http
                .post(req.url)
                .header("Content-Type", payjoin::V2_REQ_CONTENT_TYPE)
                .body(req.body)
                .send()
                .await
                .map_err(map_reqwest_err)?;

            let proposal = enrolled
                .process_res(ohttp_response.bytes().await?.to_vec().as_slice(), context)
                .map_err(|_| anyhow!("GET fallback failed"))?;
            log::debug!("got response");
            match proposal {
                Some(proposal) => break Ok(proposal),
                None => std::thread::sleep(std::time::Duration::from_secs(5)),
            }
        }
    }

    fn process_v2_proposal(
        &self,
        proposal: payjoin::receive::v2::UncheckedProposal,
    ) -> Result<payjoin::receive::v2::PayjoinProposal, Error> {
        use crate::app::try_contributing_inputs;

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

        _ = try_contributing_inputs(&mut provisional_payjoin.inner, &bitcoind)
            .map_err(|e| log::warn!("Failed to contribute inputs: {}", e));

        if !provisional_payjoin.is_output_substitution_disabled() {
            // Substitute the receiver output address.
            let receiver_substitute_address = bitcoind
                .get_new_address(None, None)
                .map_err(|e| Error::Server(e.into()))?
                .assume_checked();
            provisional_payjoin.substitute_output_address(receiver_substitute_address);
        }

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

async fn unwrap_ohttp_keys_or_else_fetch(config: &AppConfig) -> Result<payjoin::OhttpKeys> {
    if let Some(keys) = config.ohttp_keys.clone() {
        println!("Using OHTTP Keys from config");
        Ok(keys)
    } else {
        println!("Bootstrapping private network transport over Oblivious HTTP");
        let ohttp_relay = config.ohttp_relay.clone();
        let payjoin_directory = config.pj_directory.clone();
        #[cfg(feature = "danger-local-https")]
        let cert_der = rcgen::generate_simple_self_signed(vec![
            "0.0.0.0".to_string(),
            "localhost".to_string(),
        ])?
        .serialize_der()?;
        Ok(payjoin::io::fetch_ohttp_keys(
            ohttp_relay,
            payjoin_directory,
            #[cfg(feature = "danger-local-https")]
            cert_der,
        )
        .await?)
    }
}

fn map_reqwest_err(e: reqwest::Error) -> anyhow::Error {
    match e.status() {
        Some(status_code) => anyhow!("HTTP request failed: {} {}", status_code, e),
        None => anyhow!("No HTTP response: {}", e),
    }
}

struct SendStore {
    req_ctx: Option<payjoin::send::RequestContext>,
    file: std::fs::File,
}

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

struct ReceiveStore {
    session: Option<payjoin::receive::v2::Enrolled>,
    file: std::fs::File,
}

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
