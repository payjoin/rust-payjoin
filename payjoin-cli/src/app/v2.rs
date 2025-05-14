use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use payjoin::bitcoin::consensus::encode::serialize_hex;
use payjoin::bitcoin::{Amount, FeeRate};
use payjoin::persist::{PersistedError, PersistedSession, PersistedSucccessWithMaybeNoResults};
use payjoin::receive::v2::{
    replay_receiver_event_log, MaybeInputsOwned, MaybeInputsSeen, OutputsUnknown, PayjoinProposal,
    ProvisionalProposal, Receiver, ReceiverState, ReceiverWithContext, UncheckedProposal,
    UninitializedReceiver, WantsInputs, WantsOutputs,
};
use payjoin::receive::{ImplementationError, ReplyableError};
use payjoin::send::v2::{
    replay_sender_event_log, ProposalReceived, Sender, SenderBuilder, SenderState,
    SenderWithReplyKey, V2GetContext,
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
            let replay_results = replay_sender_event_log(sender_persister.clone())
                .map_err(|e| anyhow!("Failed to replay sender event log: {:?}", e))
                .ok()?;

            let pj_uri = replay_results.1.endpoint();
            let sender_state = pj_uri.filter(|uri| uri == &url).map(|_| replay_results.0);
            if let Some(sender_state) = sender_state {
                Some((sender_state, sender_persister))
            } else {
                None
            }
        });

        let (sender_state, persister) = match sender_state {
            Some((sender_state, persister)) => (sender_state, persister),
            None => {
                let persister = SenderPersister::new(self.db.clone())?;
                let psbt = self.create_original_psbt(&uri, fee_rate)?;
                let state_transition =
                    SenderBuilder::new(psbt, uri.clone()).build_recommended(fee_rate);
                let sender = persister.save_maybe_bad_init_inputs(state_transition)?;

                (SenderState::WithReplyKey(sender), persister)
            }
        };
        let mut interrupt = self.interrupt.clone();
        tokio::select! {
            _ = self.process_sender_session(sender_state, &persister) => return Ok(()),
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
        let state_transition = Receiver::<UninitializedReceiver>::create_session(
            address,
            self.config.v2()?.pj_directory.clone(),
            ohttp_keys.clone(),
            None,
        );
        let session = persister.save_maybe_bad_init_inputs(state_transition)?;
        println!("Receive session established");
        let mut pj_uri = session.pj_uri();
        pj_uri.amount = Some(amount);
        println!("Request Payjoin by sharing this Payjoin Uri:");
        println!("{}", pj_uri);
        self.process_receiver_session(ReceiverState::WithContext(session), persister).await
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
            let receiver_state = replay_receiver_event_log(recv_persister.clone())
                .map_err(|e| anyhow!("Failed to replay receiver event log: {:?}", e))?
                .0;
            tasks.push(tokio::spawn(async move {
                self_clone.process_receiver_session(receiver_state, recv_persister).await
            }));
        }

        for session_id in send_session_ids {
            let sender_persiter = SenderPersister::from_id(self.db.clone(), session_id)?;
            let sender_state = replay_sender_event_log(sender_persiter.clone())
                .map_err(|e| anyhow!("Failed to replay sender event log: {:?}", e))?
                .0;
            let self_clone = self.clone();
            tasks.push(tokio::spawn(async move {
                self_clone.process_sender_session(sender_state, &sender_persiter).await
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
    async fn process_sender_session(
        &self,
        session: SenderState,
        persister: &SenderPersister,
    ) -> Result<()> {
        match session {
            SenderState::WithReplyKey(context) => {
                // TODO: can we handle the fall back case in `post_original_proposal`. That way we don't have to clone here
                match self.post_orginal_proposal(context.clone(), persister).await {
                    Ok(()) => (),
                    Err(_) => {
                        let (req, v1_ctx) = context.extract_v1();
                        let response = post_request(req).await?;
                        let psbt =
                            Arc::new(v1_ctx.process_response(
                                &mut response.bytes().await?.to_vec().as_slice(),
                            )?);
                        self.process_pj_response((*psbt).clone())?;
                    }
                }
                return Ok(());
            }
            SenderState::V2GetContext(context) =>
                self.get_proposed_payjoin_psbt(context, persister).await?,
            SenderState::ProposalReceived(proposal) => {
                self.process_pj_response(proposal.psbt().clone())?;
                return Ok(());
            }
            _ => return Err(anyhow!("Unexpected sender state")),
        }
        return Ok(());
    }

    async fn post_orginal_proposal(
        &self,
        sender: Sender<SenderWithReplyKey>,
        persister: &SenderPersister,
    ) -> Result<()> {
        let (req, ctx) = sender.extract_v2(self.config.v2()?.ohttp_relay.clone())?;
        let response = post_request(req).await?;
        println!("Posted original proposal...");
        let state_transition = sender.process_response(&response.bytes().await?, ctx);
        let next_state = persister.save_maybe_fatal_error_transition(state_transition)?;
        self.get_proposed_payjoin_psbt(next_state, persister).await
    }

    async fn get_proposed_payjoin_psbt(
        &self,
        sender: Sender<V2GetContext>,
        persister: &SenderPersister,
    ) -> Result<()> {
        let mut session = sender.clone();
        // Long poll until we get a response
        loop {
            let (req, ctx) = session.extract_req(self.config.v2()?.ohttp_relay.clone())?;
            let response = post_request(req).await?;
            let state_transition = session.process_response(&response.bytes().await?, ctx);
            match persister.save_maybe_no_results_transition(state_transition) {
                Ok(PersistedSucccessWithMaybeNoResults::Success(psbt)) => {
                    println!("Proposal received. Processing...");
                    self.process_pj_response(psbt.psbt().clone())?;
                    return Ok(());
                }
                Ok(PersistedSucccessWithMaybeNoResults::NoResults(current_state)) => {
                    println!("No response yet.");
                    session = current_state;
                    continue;
                }
                Err(e) => {
                    println!("{}", e);
                    log::debug!("{:?}", e);
                    return Err(anyhow!("Response error").context(e));
                }
            }
        }
    }

    async fn process_receiver_session(
        &self,
        session: ReceiverState,
        persister: ReceiverPersister,
    ) -> Result<()> {
        match session {
            ReceiverState::WithContext(context) =>
                self.read_from_directory(context, None, &persister).await,
            ReceiverState::UncheckedProposal(proposal) =>
                self.check_proposal(proposal, &persister).await,
            ReceiverState::MaybeInputsOwned(proposal) =>
                self.check_inputs_not_owned(proposal, &persister).await,
            ReceiverState::MaybeInputsSeen(proposal) =>
                self.check_no_inputs_seen_before(proposal, &persister).await,
            ReceiverState::OutputsUnknown(proposal) =>
                self.identify_receiver_outputs(proposal, &persister).await,
            ReceiverState::WantsOutputs(proposal) =>
                self.commit_outputs(proposal, &persister).await,
            ReceiverState::WantsInputs(proposal) =>
                self.contribute_inputs(proposal, &persister).await,
            ReceiverState::ProvisionalProposal(proposal) =>
                self.finalize_proposal(proposal, &persister).await,
            ReceiverState::PayjoinProposal(proposal) =>
                self.send_payjoin_proposal(proposal, &persister).await,
            _ => return Err(anyhow!("Unexpected receiver state")),
        }
    }

    async fn read_from_directory(
        &self,
        session: Receiver<ReceiverWithContext>,
        amount: Option<Amount>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        println!("Receive session established");
        let mut pj_uri = session.pj_uri();
        pj_uri.amount = amount;
        println!("Request Payjoin by sharing this Payjoin Uri:");
        println!("{pj_uri}");

        let mut interrupt = self.interrupt.clone();
        let receiver = tokio::select! {
            res = self.long_poll_fallback(session, persister) => res,
            _ = interrupt.changed() => {
                println!("Interrupted. Call the `resume` command to resume all sessions.");
                return Err(anyhow!("Interrupted"));
            }
        }?;

        println!("Fallback transaction received. Consider broadcasting this to get paid if the Payjoin fails:");
        println!("{}", serialize_hex(&receiver.extract_tx_to_schedule_broadcast()));

        self.check_proposal(receiver, persister).await
    }

    async fn check_proposal(
        &self,
        proposal: Receiver<UncheckedProposal>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let wallet = self.wallet();
        // Receive Check 1: Can Broadcast
        let state_transition =
            proposal.check_broadcast_suitability(None, |tx| Ok(wallet.can_broadcast(tx)?));
        let proposal = persister.save_maybe_fatal_error_transition(state_transition)?;

        self.check_inputs_not_owned(proposal, persister).await
    }

    async fn check_inputs_not_owned(
        &self,
        proposal: Receiver<MaybeInputsOwned>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let wallet = self.wallet();
        let state_transition = proposal.check_inputs_not_owned(|input| Ok(wallet.is_mine(input)?));
        let proposal = persister.save_maybe_fatal_error_transition(state_transition)?;
        self.check_no_inputs_seen_before(proposal, persister).await
    }

    async fn check_no_inputs_seen_before(
        &self,
        proposal: Receiver<MaybeInputsSeen>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let state_transition = proposal
            .check_no_inputs_seen_before(|input| Ok(self.db.insert_input_seen_before(*input)?));
        let proposal = persister.save_maybe_fatal_error_transition(state_transition)?;
        self.identify_receiver_outputs(proposal, persister).await
    }

    async fn identify_receiver_outputs(
        &self,
        proposal: Receiver<OutputsUnknown>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let wallet = self.wallet();
        let state_transition =
            proposal.identify_receiver_outputs(|output_script| Ok(wallet.is_mine(output_script)?));
        let proposal = persister.save_maybe_fatal_error_transition(state_transition)?;
        self.commit_outputs(proposal, persister).await
    }

    async fn commit_outputs(
        &self,
        proposal: Receiver<WantsOutputs>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let state_transition = proposal.commit_outputs();
        let proposal = persister.save_progression_transition(state_transition)?;
        self.contribute_inputs(proposal, persister).await
    }

    async fn contribute_inputs(
        &self,
        proposal: Receiver<WantsInputs>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let wallet = self.wallet();
        let state_transition = proposal.contribute_inputs(wallet.list_unspent()?)?.commit_inputs();
        let proposal = persister.save_progression_transition(state_transition)?;
        self.finalize_proposal(proposal, persister).await
    }

    async fn finalize_proposal(
        &self,
        proposal: Receiver<ProvisionalProposal>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let wallet = self.wallet();
        let state_transition = proposal.finalize_proposal(
            |psbt| Ok(wallet.process_psbt(psbt)?),
            None,
            self.config.max_fee_rate,
        );
        let proposal = persister.save_maybe_transient_error_transition(state_transition)?;
        self.send_payjoin_proposal(proposal, persister).await
    }

    async fn send_payjoin_proposal(
        &self,
        mut proposal: Receiver<PayjoinProposal>,
        persister: &ReceiverPersister,
    ) -> Result<()> {
        let (req, ohttp_ctx) = proposal
            .extract_req(&self.config.v2()?.ohttp_relay)
            .map_err(|e| anyhow!("v2 req extraction failed {}", e))?;
        let res = post_request(req).await?;
        let payjoin_psbt = proposal.psbt().clone();
        let state_transition = proposal.process_res(&res.bytes().await?, ohttp_ctx);
        persister.save_maybe_success_transition(state_transition)?;
        // Note to self: session is closed by above
        println!(
            "Response successful. Watch mempool for successful Payjoin. TXID: {}",
            payjoin_psbt.extract_tx_unchecked_fee_rate().clone().compute_txid()
        );
        Ok(())
    }

    async fn long_poll_fallback(
        &self,
        session: Receiver<ReceiverWithContext>,
        persister: &ReceiverPersister,
    ) -> Result<Receiver<UncheckedProposal>> {
        let mut session = session;
        loop {
            let (req, context) = session.extract_req(&self.config.v2()?.ohttp_relay)?;
            println!("Polling receive request...");
            let ohttp_response = post_request(req).await?;
            let state_transition =
                session.process_res(ohttp_response.bytes().await?.to_vec().as_slice(), context);
            match persister.save_maybe_no_results_transition(state_transition) {
                Ok(PersistedSucccessWithMaybeNoResults::Success(next_state)) => {
                    return Ok(next_state);
                }
                Ok(PersistedSucccessWithMaybeNoResults::NoResults(current_state)) => {
                    session = current_state;
                    continue;
                }
                Err(e) => match e {
                    PersistedError::BadInitInputs(e)
                    | PersistedError::Fatal(e)
                    | PersistedError::Transient(e) => {
                        return Err(e.into());
                    }
                    PersistedError::Storage(e) => {
                        return Err(e.into());
                    }
                },
            }
        }
    }
}

/// Handle request error by sending an error response over the directory
async fn handle_recoverable_error(
    e: ReplyableError,
    mut receiver: Receiver<UncheckedProposal>,
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
    payjoin: Receiver<WantsInputs>,
    wallet: &BitcoindWallet,
    persister: &ReceiverPersister,
) -> Result<Receiver<ProvisionalProposal>, ImplementationError> {
    let candidate_inputs = wallet.list_unspent()?;

    let selected_input =
        payjoin.try_preserving_privacy(candidate_inputs).map_err(ImplementationError::from)?;

    let state_transition = payjoin
        .contribute_inputs(vec![selected_input])
        .map_err(ImplementationError::from)?
        .commit_inputs();

    let next_state = persister.save_progression_transition(state_transition)?;
    Ok(next_state)
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
