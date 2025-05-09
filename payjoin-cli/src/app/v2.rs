use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use payjoin::bitcoin::consensus::encode::serialize_hex;
use payjoin::bitcoin::{Amount, FeeRate};
use payjoin::receive::v2::{
    MaybeInputsOwned, MaybeInputsSeen, OutputsUnknown, PayjoinProposal, ProvisionalProposal,
    Receiver, ReceiverState, ReceiverWithContext, UncheckedProposal, UninitializedReceiver,
    WantsInputs, WantsOutputs,
};
use payjoin::receive::{ImplementationError, ReplyableError};
use payjoin::send::v2::{
    ProposalReceived, Sender, SenderBuilder, SenderState, SenderWithReplyKey, V2GetContext,
};
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
        let sender_state = self.db.get_send_session_ids()?.into_iter().find_map(|session_id| {
            let sender_persister = SenderPersister::from_id(self.db.clone(), session_id).ok()?;
            let mut session_history = payjoin::send::v2::SessionHistory::default();
            let sender_state = session_history
                .replay_sender_event_log(sender_persister.clone())
                .map_err(|e| anyhow!("Failed to replay sender event log: {:?}", e))
                .ok()?;

            let pj_uri = session_history.endpoint();
            pj_uri.filter(|uri| uri == &url).map(|_| sender_state)
        });

        let sender_state = match sender_state {
            Some(sender_state) => sender_state,
            None => {
                let sender_persister = SenderPersister::new(self.db.clone())?;
                let psbt = self.create_original_psbt(&uri, fee_rate)?;
                let sender = SenderBuilder::new(psbt, uri.clone(), sender_persister.clone())
                    .build_recommended(fee_rate)
                    .with_context(|| "Failed to build payjoin request")?;
                SenderState::WithReplyKey(sender)
            }
        };
        let mut interrupt = self.interrupt.clone();
        tokio::select! {
            _ = self.process_sender_session(sender_state) => return Ok(()),
            _ = interrupt.changed() => {
                println!("Interrupted. Call `send` with the same arguments to resume this session or `resume` to resume all sessions.");
                return Err(anyhow!("Interrupted"))
            }
        }
    }

    async fn receive_payjoin(&self, amount: Amount) -> Result<()> {
        let address = self.wallet().get_new_address()?;
        let ohttp_keys = unwrap_ohttp_keys_or_else_fetch(&self.config).await?;
        let persister = ReceiverPersister::new(self.db.clone())?;
        let session = Receiver::<UninitializedReceiver, ReceiverPersister>::create_session(
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
        self.process_receiver_session(ReceiverState::WithContext(session)).await
    }

    #[allow(clippy::incompatible_msrv)]
    async fn resume_payjoins(&self) -> Result<()> {
        let recv_session_ids = self.db.get_recv_session_ids()?;
        let send_session_ids = self.db.get_send_session_ids()?;
        if recv_session_ids.is_empty() && send_session_ids.is_empty() {
            println!("No sessions to resume.");
            return Ok(());
        }

        let mut tasks = Vec::new();

        for session_id in recv_session_ids {
            let self_clone = self.clone();
            let recv_persister = ReceiverPersister::from_id(self.db.clone(), session_id)?;
            let receiver_state = payjoin::receive::v2::SessionHistory::default()
                .replay_receiver_event_log(recv_persister.clone())
                .map_err(|e| anyhow!("Failed to replay receiver event log: {:?}", e))?;
            tasks.push(tokio::spawn(async move {
                self_clone.process_receiver_session(receiver_state).await
            }));
        }

        for session_id in send_session_ids {
            let sender_persiter = SenderPersister::from_id(self.db.clone(), session_id)?;
            let sender_state = payjoin::send::v2::SessionHistory::default()
                .replay_sender_event_log(sender_persiter.clone())
                .map_err(|e| anyhow!("Failed to replay sender event log: {:?}", e))?;
            let self_clone = self.clone();
            tasks.push(tokio::spawn(async move {
                self_clone.process_sender_session(sender_state).await
            }));
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
        // TODO: re-enable this. We want to display certain session details for each closed and pending session.
        // Thes details can be obtained by replaying the event logs and querying the `SessionHistory` for each session.
        // let send_sessions = self.db.get_send_sessions()?;
        // let recv_sessions = self.db.get_recv_sessions()?;
        // let closed_send_sessions = self.db.get_closed_send_sessions()?;
        // let closed_recv_sessions = self.db.get_closed_recv_sessions()?;

        // println!("Open send sessions: {:?}", send_sessions.len());
        // for session in send_sessions {
        //     println!("Send session: {:?}", session);
        // }
        // println!("Open recv sessions: {:?}", recv_sessions.len());
        // for session in recv_sessions {
        //     println!("Recv session: {:?}", session);
        // }
        // println!("Closed send sessions: {:?}", closed_send_sessions.len());
        // for session in closed_send_sessions {
        //     println!("Closed send session: {:?}", session);
        // }
        // println!("Closed recv sessions: {:?}", closed_recv_sessions.len());
        // for session in closed_recv_sessions {
        //     println!("Closed recv session: {:?}", session);
        // }
        Ok(())
    }
}

impl App {
    async fn process_sender_session(&self, session: SenderState<SenderPersister>) -> Result<()> {
        let mut session = session.clone();
        loop {
            match session {
                SenderState::WithReplyKey(context) => {
                    match self.post_orginal_proposal(&context).await {
                        Ok(sender) => session = SenderState::V2GetContext(sender),
                        Err(_) => {
                            let (req, v1_ctx) = context.extract_v1();
                            let response = post_request(req).await?;
                            let psbt = Arc::new(v1_ctx.process_response(
                                &mut response.bytes().await?.to_vec().as_slice(),
                            )?);
                            self.process_pj_response((*psbt).clone())?;
                            return Ok(());
                        }
                    }
                }

                SenderState::V2GetContext(context) => {
                    session = SenderState::ProposalReceived(
                        self.get_proposed_payjoin_psbt(&context).await?,
                    );
                }

                SenderState::ProposalReceived(proposal) => {
                    let psbt = proposal.psbt().clone();
                    self.process_pj_response(psbt)?;
                    return Ok(());
                }
                _ => return Err(anyhow!("Unexpected sender state")),
            }
        }
    }

    async fn post_orginal_proposal(
        &self,
        sender: &Sender<SenderWithReplyKey, SenderPersister>,
    ) -> Result<Sender<V2GetContext, SenderPersister>> {
        let (req, ctx) = sender.extract_v2(self.config.v2()?.ohttp_relay.clone())?;
        let response = post_request(req).await?;
        // TODO: clone here smells
        let v2_ctx = sender.clone().process_response(&response.bytes().await?, ctx)?;
        Ok(v2_ctx)
    }

    async fn get_proposed_payjoin_psbt(
        &self,
        sender: &Sender<V2GetContext, SenderPersister>,
    ) -> Result<Sender<ProposalReceived, SenderPersister>> {
        // Long poll until we get a response
        loop {
            let (req, ctx) = sender.extract_req(self.config.v2()?.ohttp_relay.clone())?;
            let response = post_request(req).await?;
            match sender.process_response(&response.bytes().await?, ctx) {
                Ok(Some(psbt)) => return Ok(psbt),
                Ok(None) => {
                    println!("No response yet.");
                }
                Err(re) => {
                    println!("{}", re);
                    log::debug!("{:?}", re);
                    return Err(anyhow!("Response error").context(re));
                }
            }
        }
    }

    async fn process_receiver_session(
        &self,
        session: ReceiverState<ReceiverPersister>,
    ) -> Result<()> {
        let mut session = session.clone();
        loop {
            match session {
                ReceiverState::WithContext(context) =>
                    session = ReceiverState::UncheckedProposal(
                        self.read_from_directory(context, None).await?,
                    ),
                ReceiverState::UncheckedProposal(proposal) =>
                    session = ReceiverState::MaybeInputsOwned(self.check_proposal(proposal)?),
                ReceiverState::MaybeInputsOwned(proposal) =>
                    session = ReceiverState::MaybeInputsSeen(self.check_inputs_not_owned(proposal)?),
                ReceiverState::MaybeInputsSeen(proposal) =>
                    session =
                        ReceiverState::OutputsUnknown(self.check_no_inputs_seen_before(proposal)?),
                ReceiverState::OutputsUnknown(proposal) =>
                    session = ReceiverState::WantsOutputs(self.identify_receiver_outputs(proposal)?),
                ReceiverState::WantsOutputs(proposal) =>
                    session = ReceiverState::WantsInputs(self.commit_outputs(proposal)?),
                ReceiverState::WantsInputs(proposal) =>
                    session = ReceiverState::ProvisionalProposal(self.contribute_inputs(proposal)?),
                ReceiverState::ProvisionalProposal(proposal) =>
                    session = ReceiverState::PayjoinProposal(self.finalize_proposal(proposal)?),
                ReceiverState::PayjoinProposal(proposal) => {
                    self.send_payjoin_proposal(proposal).await?;
                    return Ok(());
                }
                _ => return Err(anyhow!("Unexpected receiver state")),
            }
        }
    }

    async fn read_from_directory(
        &self,
        mut session: Receiver<ReceiverWithContext, ReceiverPersister>,
        amount: Option<Amount>,
    ) -> Result<Receiver<UncheckedProposal, ReceiverPersister>> {
        println!("Receive session established");
        let mut pj_uri = session.pj_uri();
        pj_uri.amount = amount;
        println!("Request Payjoin by sharing this Payjoin Uri:");
        println!("{pj_uri}");

        let mut interrupt = self.interrupt.clone();
        let receiver = tokio::select! {
            res = self.long_poll_fallback(&mut session) => res,
            _ = interrupt.changed() => {
                println!("Interrupted. Call the `resume` command to resume all sessions.");
                return Err(anyhow!("Interrupted"));
            }
        }?;

        println!("Fallback transaction received. Consider broadcasting this to get paid if the Payjoin fails:");
        println!("{}", serialize_hex(&receiver.extract_tx_to_schedule_broadcast()));
        Ok(receiver)
    }

    fn check_proposal(
        &self,
        proposal: Receiver<UncheckedProposal, ReceiverPersister>,
    ) -> Result<Receiver<MaybeInputsOwned, ReceiverPersister>> {
        let wallet = self.wallet();
        // Receive Check 1: Can Broadcast
        let proposal =
            proposal.check_broadcast_suitability(None, |tx| Ok(wallet.can_broadcast(tx)?))?;

        Ok(proposal)
    }

    fn check_inputs_not_owned(
        &self,
        proposal: Receiver<MaybeInputsOwned, ReceiverPersister>,
    ) -> Result<Receiver<MaybeInputsSeen, ReceiverPersister>> {
        let wallet = self.wallet();
        let proposal = proposal.check_inputs_not_owned(|input| Ok(wallet.is_mine(input)?))?;
        Ok(proposal)
    }

    fn check_no_inputs_seen_before(
        &self,
        proposal: Receiver<MaybeInputsSeen, ReceiverPersister>,
    ) -> Result<Receiver<OutputsUnknown, ReceiverPersister>> {
        let proposal = proposal
            .check_no_inputs_seen_before(|input| Ok(self.db.insert_input_seen_before(*input)?))?;
        Ok(proposal)
    }

    fn identify_receiver_outputs(
        &self,
        proposal: Receiver<OutputsUnknown, ReceiverPersister>,
    ) -> Result<Receiver<WantsOutputs, ReceiverPersister>> {
        let wallet = self.wallet();
        let proposal = proposal
            .identify_receiver_outputs(|output_script| Ok(wallet.is_mine(output_script)?))?;
        Ok(proposal)
    }
    fn commit_outputs(
        &self,
        proposal: Receiver<WantsOutputs, ReceiverPersister>,
    ) -> Result<Receiver<WantsInputs, ReceiverPersister>> {
        let proposal = proposal.commit_outputs();
        Ok(proposal)
    }

    fn contribute_inputs(
        &self,
        proposal: Receiver<WantsInputs, ReceiverPersister>,
    ) -> Result<Receiver<ProvisionalProposal, ReceiverPersister>> {
        let wallet = self.wallet();
        let proposal = proposal.contribute_inputs(wallet.list_unspent()?)?.commit_inputs();
        Ok(proposal)
    }

    fn finalize_proposal(
        &self,
        proposal: Receiver<ProvisionalProposal, ReceiverPersister>,
    ) -> Result<Receiver<PayjoinProposal, ReceiverPersister>> {
        let wallet = self.wallet();
        let proposal = proposal.finalize_proposal(
            |psbt| Ok(wallet.process_psbt(psbt)?),
            None,
            self.config.max_fee_rate,
        )?;
        Ok(proposal)
    }

    async fn send_payjoin_proposal(
        &self,
        mut proposal: Receiver<PayjoinProposal, ReceiverPersister>,
    ) -> Result<()> {
        let (req, ohttp_ctx) = proposal
            .extract_req(&self.config.v2()?.ohttp_relay)
            .map_err(|e| anyhow!("v2 req extraction failed {}", e))?;
        let res = post_request(req).await?;
        proposal
            .process_res(&res.bytes().await?, ohttp_ctx)
            .map_err(|e| anyhow!("Failed to deserialize response {}", e))?;
        let payjoin_psbt = proposal.psbt().clone();
        println!(
            "Response successful. Watch mempool for successful Payjoin. TXID: {}",
            payjoin_psbt.extract_tx_unchecked_fee_rate().clone().compute_txid()
        );
        Ok(())
    }

    async fn long_poll_fallback(
        &self,
        session: &mut Receiver<ReceiverWithContext, ReceiverPersister>,
    ) -> Result<Receiver<UncheckedProposal, ReceiverPersister>> {
        loop {
            let (req, context) = session.extract_req(&self.config.v2()?.ohttp_relay)?;
            println!("Polling receive request...");
            let ohttp_response = post_request(req).await?;
            let proposal = session
                .process_res(ohttp_response.bytes().await?.to_vec().as_slice(), context)
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
    mut receiver: Receiver<UncheckedProposal, ReceiverPersister>,
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
    payjoin: Receiver<WantsInputs, ReceiverPersister>,
    wallet: &BitcoindWallet,
) -> Result<Receiver<ProvisionalProposal, ReceiverPersister>, ImplementationError> {
    let candidate_inputs = wallet.list_unspent()?;

    let selected_input =
        payjoin.try_preserving_privacy(candidate_inputs).map_err(ImplementationError::from)?;

    Ok(payjoin
        .contribute_inputs(vec![selected_input])
        .map_err(ImplementationError::from)?
        .commit_inputs())
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
