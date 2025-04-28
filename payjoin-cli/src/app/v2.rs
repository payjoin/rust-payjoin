use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use log::error;
use payjoin::bitcoin::consensus::encode::serialize_hex;
use payjoin::bitcoin::psbt::Psbt;
use payjoin::bitcoin::{Amount, FeeRate};
use payjoin::persist::PersistedSession;
use payjoin::receive::v2::{
    replay_receiver_event_log, MaybeInputsOwned, MaybeInputsSeen, OutputsUnknown, PayjoinProposal,
    ProvisionalProposal, ReceiverState, ReceiverWithContext, UncheckedProposal,
    UninitializedReceiver, WantsInputs,
};
use payjoin::receive::{Error, ImplementationError, ReplyableError};
use payjoin::send::v2::{Sender, SenderBuilder, SenderSessionEvent};
use payjoin::Uri;
use tokio::sync::watch;

use super::config::Config;
use super::wallet::BitcoindWallet;
use super::App as AppTrait;
use crate::app::{handle_interrupt, http_agent};
use crate::db::v2::{ReceiverPersister, SenderPersister};
use crate::db::Database;

#[derive(Clone)]
pub(crate) struct App {
    config: Config,
    db: Arc<Database>,
    wallet: BitcoindWallet,
    interrupt: watch::Receiver<()>,
}

#[async_trait::async_trait]
impl AppTrait for App {
    fn new(config: Config) -> Result<Self> {
        let db = Arc::new(Database::create(&config.db_path)?);
        let (interrupt_tx, interrupt_rx) = watch::channel(());
        tokio::spawn(handle_interrupt(interrupt_tx));
        let wallet = BitcoindWallet::new(&config.bitcoind)?;
        let app = Self { config, db, wallet, interrupt: interrupt_rx };
        app.wallet()
            .network()
            .context("Failed to connect to bitcoind. Check config RPC connection.")?;
        Ok(app)
    }

    fn wallet(&self) -> BitcoindWallet { self.wallet.clone() }

    async fn send_payjoin(&self, bip21: &str, fee_rate: FeeRate) -> Result<()> {
        use payjoin::UriExt;
        let uri =
            Uri::try_from(bip21).map_err(|e| anyhow!("Failed to create URI from BIP21: {}", e))?;
        let uri = uri.assume_checked();
        let uri = uri.check_pj_supported().map_err(|_| anyhow!("URI does not support Payjoin"))?;
        let url = uri.extras.endpoint();
        // If sender session exists, resume it
        // TODO: need to replay the events not just read the first one
        for session in self.db.get_send_sessions()? {
            let created_event = session.events.first().unwrap().clone();
            if let SenderSessionEvent::Created(sender) = created_event {
                if sender.endpoint() == url {
                    return self.spawn_payjoin_sender(sender).await;
                }
            }
        }
        let psbt = self.create_original_psbt(&uri, fee_rate)?;
        let mut persister = SenderPersister::new(self.db.clone())?;
        // TODO: new sender will be replaced with uninitialized sender a
        let new_sender = SenderBuilder::new(psbt, uri.clone())
            .build_recommended(fee_rate)
            .with_context(|| "Failed to build payjoin request")?;
        new_sender
            .persist(&mut persister)
            .map_err(|e| anyhow!("Failed to persist sender: {}", e))?;
        let events = persister.load()?.next().expect("Just created sender");

        let sender = match events {
            SenderSessionEvent::Created(sender) => sender,
            _ => return Err(anyhow!("Failed to load sender: could not find created event")),
        };

        self.spawn_payjoin_sender(sender).await
    }

    async fn receive_payjoin(&self, amount: Amount) -> Result<()> {
        let address = self.wallet().get_new_address()?;
        let ohttp_keys = unwrap_ohttp_keys_or_else_fetch(&self.config).await?;
        let persister = ReceiverPersister::new(self.db.clone())?;
        let session = UninitializedReceiver::create_session(
            address,
            self.config.v2()?.pj_directory.clone(),
            ohttp_keys.clone(),
            None,
            persister.clone(),
        )?;
        println!("Receive session established");
        let mut pj_uri = session.pj_uri();
        pj_uri.amount = Some(amount);
        println!("Request Payjoin by sharing this Payjoin Uri:");
        println!("{}", pj_uri);
        self.process_receiver_session(ReceiverState::WithContext(session), persister).await
    }

    #[allow(clippy::incompatible_msrv)]
    async fn resume_payjoins(&self) -> Result<()> {
        let recv_sessions = self.db.get_recv_sessions()?;
        let send_sessions = self.db.get_send_sessions()?;

        if recv_sessions.is_empty() && send_sessions.is_empty() {
            println!("No sessions to resume.");
            return Ok(());
        }

        let mut tasks = Vec::new();

        for session_id in self.db.get_recv_session_ids()? {
            let self_clone = self.clone();
            let recv_persister = ReceiverPersister::from_id(self.db.clone(), session_id)?;
            let receiver_state = replay_receiver_event_log(recv_persister.clone())
                .map_err(|e| anyhow!("Failed to replay receiver event log: {:?}", e))?;
            tasks.push(tokio::spawn(async move {
                self_clone.process_receiver_session(receiver_state, recv_persister).await
            }));
        }

        for session in send_sessions {
            let self_clone = self.clone();
            // TODO: should replay the events not just read the first one
            let created_event = session.events.first().unwrap().clone();
            println!("created_event: {:?}", created_event);
            if let SenderSessionEvent::Created(sender) = created_event {
                tasks.push(tokio::spawn(async move {
                    self_clone.spawn_payjoin_sender(sender.clone()).await
                }));
            } else {
                error!("First event is not a sender");
            }
        }

        let mut interrupt = self.interrupt.clone();
        tokio::select! {
            _ = async {
                for task in tasks {
                    let _ = task.await;
                }
            } => {
                println!("All resumed sessions completed.");
            }
            _ = interrupt.changed() => {
                println!("Resumed sessions were interrupted.");
            }
        }
        Ok(())
    }

    #[cfg(feature = "v2")]
    async fn history(&self) -> Result<()> {
        let send_sessions = self.db.get_send_sessions()?;
        let recv_sessions = self.db.get_recv_sessions()?;
        let closed_send_sessions = self.db.get_closed_send_sessions()?;
        let closed_recv_sessions = self.db.get_closed_recv_sessions()?;

        println!("Open send sessions: {:?}", send_sessions.len());
        for session in send_sessions {
            println!("Send session: {:?}", session);
        }
        println!("Open recv sessions: {:?}", recv_sessions.len());
        for session in recv_sessions {
            println!("Recv session: {:?}", session);
        }
        println!("Closed send sessions: {:?}", closed_send_sessions.len());
        for session in closed_send_sessions {
            println!("Closed send session: {:?}", session);
        }
        println!("Closed recv sessions: {:?}", closed_recv_sessions.len());
        for session in closed_recv_sessions {
            println!("Closed recv session: {:?}", session);
        }
        Ok(())
    }
}

impl App {
    #[allow(clippy::incompatible_msrv)]
    async fn spawn_payjoin_sender(&self, mut req_ctx: Sender) -> Result<()> {
        let mut interrupt = self.interrupt.clone();
        tokio::select! {
            res = self.long_poll_post(&mut req_ctx) => {
                self.process_pj_response(res?)?;
                // TODO: use persister session to close
                // self.db.close_send_session(req_ctx.endpoint())?;
            }
            _ = interrupt.changed() => {
                println!("Interrupted. Call `send` with the same arguments to resume this session or `resume` to resume all sessions.");
            }
        }
        Ok(())
    }

    async fn process_receiver_session(
        &self,
        session: ReceiverState,
        persister: ReceiverPersister,
    ) -> Result<()> {
        let mut state = session.clone();
        loop {
            match state {
                ReceiverState::WithContext(context) => {
                    state = self.read_from_directory(context, None, persister.clone()).await?;
                }
                ReceiverState::UncheckedProposal(proposal) => {
                    state = self.check_proposal(proposal, persister.clone())?;
                }
                ReceiverState::MaybeInputsOwned(proposal) => {
                    state = self.check_inputs_not_owned(proposal, persister.clone())?;
                }
                ReceiverState::MaybeInputsSeen(proposal) => {
                    state = self.check_no_inputs_seen_before(proposal, persister.clone())?;
                }
                ReceiverState::OutputsUnknown(proposal) => {
                    state = self.identify_receiver_outputs(proposal, persister.clone())?;
                }
                ReceiverState::WantsOutputs(proposal) => {
                    state = self.commit_outputs(proposal, persister.clone())?;
                }
                ReceiverState::WantsInputs(proposal) => {
                    state = self.contribute_inputs(proposal, persister.clone())?;
                }
                ReceiverState::ProvisionalProposal(proposal) => {
                    state = self.finalize_proposal(proposal, persister.clone())?;
                }
                ReceiverState::PayjoinProposal(proposal) => {
                    self.send_payjoin_proposal(proposal, persister.clone()).await?;
                    return Ok(());
                }
                _ => return Err(anyhow!("Unexpected receiver state: {:?}", state)),
            }
        }
    }

    async fn read_from_directory(
        &self,
        mut session: ReceiverWithContext,
        amount: Option<Amount>,
        persister: ReceiverPersister,
    ) -> Result<ReceiverState> {
        println!("Receive session established");
        let mut pj_uri = session.pj_uri();
        pj_uri.amount = amount;
        println!("Request Payjoin by sharing this Payjoin Uri:");
        println!("{pj_uri}");

        let mut interrupt = self.interrupt.clone();
        let receiver = tokio::select! {
            res = self.long_poll_fallback(&mut session, persister.clone()) => res,
            _ = interrupt.changed() => {
                println!("Interrupted. Call the `resume` command to resume all sessions.");
                return Err(anyhow!("Interrupted"));
            }
        }?;

        println!("Fallback transaction received. Consider broadcasting this to get paid if the Payjoin fails:");
        println!("{}", serialize_hex(&receiver.extract_tx_to_schedule_broadcast()));
        Ok(ReceiverState::UncheckedProposal(receiver))
    }

    fn check_proposal(
        &self,
        proposal: UncheckedProposal,
        persister: ReceiverPersister,
    ) -> Result<ReceiverState> {
        let wallet = self.wallet();
        // Receive Check 1: Can Broadcast
        let proposal = proposal.check_broadcast_suitability(
            None,
            |tx| Ok(wallet.can_broadcast(tx)?),
            persister.clone(),
        )?;
        log::trace!("check1");

        Ok(ReceiverState::MaybeInputsOwned(proposal))
    }

    fn check_inputs_not_owned(
        &self,
        proposal: MaybeInputsOwned,
        persister: ReceiverPersister,
    ) -> Result<ReceiverState> {
        let wallet = self.wallet();
        let proposal = proposal
            .check_inputs_not_owned(|input| Ok(wallet.is_mine(input)?), persister.clone())?;
        Ok(ReceiverState::MaybeInputsSeen(proposal))
    }

    fn check_no_inputs_seen_before(
        &self,
        proposal: MaybeInputsSeen,
        persister: ReceiverPersister,
    ) -> Result<ReceiverState> {
        let proposal = proposal.check_no_inputs_seen_before(
            |input| Ok(self.db.insert_input_seen_before(*input)?),
            persister.clone(),
        )?;
        Ok(ReceiverState::OutputsUnknown(proposal))
    }

    fn identify_receiver_outputs(
        &self,
        proposal: OutputsUnknown,
        persister: ReceiverPersister,
    ) -> Result<ReceiverState> {
        let wallet = self.wallet();
        let proposal = proposal.identify_receiver_outputs(
            |output_script| Ok(wallet.is_mine(output_script)?),
            persister.clone(),
        )?;
        Ok(ReceiverState::WantsOutputs(proposal))
    }
    fn commit_outputs(
        &self,
        proposal: payjoin::receive::v2::WantsOutputs,
        persister: ReceiverPersister,
    ) -> Result<ReceiverState> {
        let proposal = proposal.commit_outputs(persister.clone());
        Ok(ReceiverState::WantsInputs(proposal))
    }

    fn contribute_inputs(
        &self,
        proposal: WantsInputs,
        persister: ReceiverPersister,
    ) -> Result<ReceiverState> {
        let wallet = self.wallet();
        let proposal =
            proposal.contribute_inputs(wallet.list_unspent()?)?.commit_inputs(persister.clone());
        Ok(ReceiverState::ProvisionalProposal(proposal))
    }

    fn finalize_proposal(
        &self,
        proposal: ProvisionalProposal,
        persister: ReceiverPersister,
    ) -> Result<ReceiverState> {
        let wallet = self.wallet();
        let proposal = proposal.finalize_proposal(
            |psbt| Ok(wallet.process_psbt(psbt)?),
            None,
            self.config.max_fee_rate,
            persister.clone(),
        )?;
        Ok(ReceiverState::PayjoinProposal(proposal))
    }

    async fn send_payjoin_proposal(
        &self,
        mut proposal: PayjoinProposal,
        persister: ReceiverPersister,
    ) -> Result<()> {
        let (req, ohttp_ctx) = proposal
            .extract_req(&self.config.v2()?.ohttp_relay)
            .map_err(|e| anyhow!("v2 req extraction failed {}", e))?;
        let res = post_request(req).await?;
        proposal
            .process_res(&res.bytes().await?, ohttp_ctx, persister.clone())
            .map_err(|e| anyhow!("Failed to deserialize response {}", e))?;
        let payjoin_psbt = proposal.psbt().clone();
        println!(
            "Response successful. Watch mempool for successful Payjoin. TXID: {}",
            payjoin_psbt.extract_tx_unchecked_fee_rate().clone().compute_txid()
        );
        Ok(())
    }

    async fn long_poll_post(&self, req_ctx: &mut Sender) -> Result<Psbt> {
        match req_ctx.extract_v2(self.config.v2()?.ohttp_relay.clone()) {
            Ok((req, ctx)) => {
                println!("Posting Original PSBT Payload request...");
                let response = post_request(req).await?;
                println!("Sent fallback transaction");
                let v2_ctx = Arc::new(ctx.process_response(&response.bytes().await?)?);
                loop {
                    let (req, ohttp_ctx) =
                        v2_ctx.extract_req(self.config.v2()?.ohttp_relay.clone())?;
                    let response = post_request(req).await?;
                    match v2_ctx.process_response(&response.bytes().await?, ohttp_ctx) {
                        Ok(Some(psbt)) => return Ok(psbt),
                        Ok(None) => {
                            println!("No response yet.");
                        }
                        Err(re) => {
                            println!("{re}");
                            log::debug!("{re:?}");
                            return Err(anyhow!("Response error").context(re));
                        }
                    }
                }
            }
            Err(_) => {
                let (req, v1_ctx) = req_ctx.extract_v1();
                println!("Posting Original PSBT Payload request...");
                let response = post_request(req).await?;
                println!("Sent fallback transaction");
                match v1_ctx.process_response(&mut response.bytes().await?.to_vec().as_slice()) {
                    Ok(psbt) => Ok(psbt),
                    Err(re) => {
                        println!("{re}");
                        log::debug!("{re:?}");
                        Err(anyhow!("Response error").context(re))
                    }
                }
            }
        }
    }

    async fn long_poll_fallback(
        &self,
        session: &mut ReceiverWithContext,
        persister: ReceiverPersister,
    ) -> Result<payjoin::receive::v2::UncheckedProposal> {
        loop {
            let (req, context) = session.extract_req(&self.config.v2()?.ohttp_relay)?;
            println!("Polling receive request...");
            let ohttp_response = post_request(req).await?;
            let proposal = session
                .process_res(
                    ohttp_response.bytes().await?.to_vec().as_slice(),
                    context,
                    persister.clone(),
                )
                .map_err(|_| anyhow!("GET fallback failed"))?;
            log::debug!("got response");
            if let Some(proposal) = proposal {
                break Ok(proposal);
            }
        }
    }
}

/// Handle request error by sending an error response over the directory
async fn handle_recoverable_error(
    e: ReplyableError,
    mut receiver: payjoin::receive::v2::UncheckedProposal,
    ohttp_relay: &payjoin::Url,
) -> anyhow::Error {
    let to_return = anyhow!("Replied with error: {}", e);
    let (err_req, err_ctx) = match receiver.extract_err_req(&e.into(), ohttp_relay) {
        Ok(req_ctx) => req_ctx,
        Err(e) => return anyhow!("Failed to extract error request: {}", e),
    };

    let err_response = match post_request(err_req).await {
        Ok(response) => response,
        Err(e) => return anyhow!("Failed to post error request: {}", e),
    };

    let err_bytes = match err_response.bytes().await {
        Ok(bytes) => bytes,
        Err(e) => return anyhow!("Failed to get error response bytes: {}", e),
    };

    if let Err(e) = receiver.process_err_res(&err_bytes, err_ctx) {
        return anyhow!("Failed to process error response: {}", e);
    }

    to_return
}

fn try_contributing_inputs(
    payjoin: payjoin::receive::v2::WantsInputs,
    wallet: &BitcoindWallet,
    persister: ReceiverPersister,
) -> Result<payjoin::receive::v2::ProvisionalProposal, ImplementationError> {
    let candidate_inputs = wallet.list_unspent()?;

    let selected_input =
        payjoin.try_preserving_privacy(candidate_inputs).map_err(ImplementationError::from)?;

    Ok(payjoin
        .contribute_inputs(vec![selected_input])
        .map_err(ImplementationError::from)?
        .commit_inputs(persister.clone()))
}

async fn unwrap_ohttp_keys_or_else_fetch(config: &Config) -> Result<payjoin::OhttpKeys> {
    if let Some(keys) = config.v2()?.ohttp_keys.clone() {
        println!("Using OHTTP Keys from config");
        Ok(keys)
    } else {
        println!("Bootstrapping private network transport over Oblivious HTTP");
        let ohttp_relay = config.v2()?.ohttp_relay.clone();
        let payjoin_directory = config.v2()?.pj_directory.clone();
        #[cfg(feature = "_danger-local-https")]
        let ohttp_keys = {
            let cert_der = crate::app::read_local_cert()?;
            payjoin::io::fetch_ohttp_keys_with_cert(ohttp_relay, payjoin_directory, cert_der)
                .await?
        };
        #[cfg(not(feature = "_danger-local-https"))]
        let ohttp_keys = payjoin::io::fetch_ohttp_keys(ohttp_relay, payjoin_directory).await?;
        Ok(ohttp_keys)
    }
}

async fn post_request(req: payjoin::Request) -> Result<reqwest::Response> {
    let http = http_agent()?;
    http.post(req.url)
        .header("Content-Type", req.content_type)
        .body(req.body)
        .send()
        .await
        .map_err(map_reqwest_err)
}

fn map_reqwest_err(e: reqwest::Error) -> anyhow::Error {
    match e.status() {
        Some(status_code) => anyhow!("HTTP request failed: {} {}", status_code, e),
        None => anyhow!("No HTTP response: {}", e),
    }
}
