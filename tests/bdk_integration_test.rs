use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard};

use bdk::bitcoin::psbt::PartiallySignedTransaction;
use bdk::bitcoin::{Address, Network, Script, Transaction};
use bdk::blockchain::EsploraBlockchain;
use bdk::database::MemoryDatabase;
use bdk::wallet::AddressIndex;
use bdk::{FeeRate, LocalUtxo, SignOptions, Wallet as BdkWallet};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use payjoin_ffi::error::PayjoinError;
use payjoin_ffi::receive::v1::{Headers, PayjoinProposal, UncheckedProposal};
use payjoin_ffi::types::{OutPoint, Request, TxOut};
use payjoin_ffi::uri::{PjUri, Uri};
use uniffi::deps::log::debug;

// Set up RPC connections
static RPC_USER: &str = "admin1";
static RPC_PASSWORD: &str = "123";
static RPC_HOST: &str = "localhost";
static RPC_PORT: &str = "18443";
static ESPLORA_URL: &str = "http://0.0.0.0:30000";
type BoxError = Box<dyn std::error::Error + 'static>;
pub struct EsploraClient(EsploraBlockchain);

impl EsploraClient {
    pub fn new(url: String) -> Self {
        let client = EsploraBlockchain::new(url.as_str(), 10);
        Self(client)
    }

    #[allow(dead_code)]
    pub fn broadcast(&self, transaction: Transaction) -> Result<(), BoxError> {
        match self.0.broadcast(&transaction) {
            Ok(_) => Ok(()),
            Err(e) => panic!("{}", e.to_string()),
        }
    }
}

fn restore_wallet(descriptor: String) -> Result<Wallet, BoxError> {
    match Wallet::new_no_persist(descriptor.to_string(), Network::Regtest) {
        Ok(e) => Ok(e),
        Err(e) => panic!("{}", e.to_string()),
    }
}

fn get_bitcoin_client() -> Client {
    let url = format!("http://{}:{}/wallet/{}", RPC_HOST, RPC_PORT, "");
    Client::new(&*url, Auth::UserPass(RPC_USER.to_string(), RPC_PASSWORD.to_string())).unwrap()
}

fn restore_esplora_client() -> EsploraClient {
    EsploraClient::new(ESPLORA_URL.to_string())
}
fn init_sender_receiver_wallet() -> (Wallet, Wallet, Client) {
    let sender = restore_wallet(get_sender_descriptor()).expect("Wallet::new failed");
    let receiver = restore_wallet(get_receiver_descriptor()).expect("Wallet::new failed");
    let client = get_bitcoin_client();
    let esplora_client = restore_esplora_client();
    let receiver_address = receiver.get_address(AddressIndex::New);
    let sender_address = sender.get_address(AddressIndex::New);
    let sender_balance = sender.get_balance().to_string();
    let receiver_balance = receiver.get_balance().to_string();

    client
        .send_to_address(
            &bitcoincore_rpc::bitcoin::address::Address::from_str(&*receiver_address.to_string())
                .unwrap()
                .assume_checked(),
            bitcoincore_rpc::bitcoin::Amount::ONE_BTC,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
    client
        .send_to_address(
            &bitcoincore_rpc::bitcoin::address::Address::from_str(&*sender_address.to_string())
                .unwrap()
                .assume_checked(),
            bitcoincore_rpc::bitcoin::Amount::ONE_BTC,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap();
    client
        .generate_to_address(
            11,
            &bitcoincore_rpc::bitcoin::address::Address::from_str(&*receiver_address.to_string())
                .unwrap()
                .assume_checked(),
        )
        .expect("generate failed");
    let _ = sender.sync(&esplora_client);
    let _ = receiver.sync(&esplora_client);
    println!("\n Sender balance: {:?}", receiver.get_balance());
    println!("\n Receiver balance: {:?}", sender.get_balance());
    assert_ne!(receiver_balance, receiver.get_balance(), "receiver doesn't own bitcoin");

    assert_ne!(sender_balance, sender.get_balance(), "sender doesn't own bitcoin");
    (sender, receiver, client)
}

#[allow(dead_code)]
fn broadcast_tx(esplora_client: EsploraClient, tx: Transaction) -> Result<(), BoxError> {
    esplora_client.broadcast(tx)
}
fn build_pj_uri<'a>(
    address: String,
    amount: u64,
    pj: &str,
    ohttp: Option<&str>,
) -> Result<Uri, BoxError> {
    let pj_uri_string =
        format!("{}?amount={}&pj={}", address, (amount as f64 / 100_000_000.0), pj,);
    if let Some(ohttp) = ohttp {
        format!("{} {} {}", pj_uri_string, "&ohttp={}", ohttp);
    }
    debug!("PJ URI: {}", &pj_uri_string);
    match Uri::from_str(pj_uri_string) {
        Ok(e) => Ok(e),
        Err(e) => panic!("{}", e.to_string()),
    }
}
#[derive(Debug)]
pub struct Wallet {
    inner_mutex: Mutex<BdkWallet<MemoryDatabase>>,
}

impl Wallet {
    pub fn new_no_persist(descriptor: String, network: Network) -> Result<Self, BoxError> {
        let wallet =
            BdkWallet::new(descriptor.as_str(), None, network.into(), MemoryDatabase::new())?;

        Ok(Wallet { inner_mutex: Mutex::new(wallet) })
    }

    pub(crate) fn get_wallet(&self) -> MutexGuard<BdkWallet<MemoryDatabase>> {
        self.inner_mutex.lock().expect("wallet")
    }

    pub fn get_address(&self, address_index: AddressIndex) -> Address {
        self.get_wallet().get_address(address_index.into()).unwrap().address
    }

    pub fn get_balance(&self) -> String {
        self.get_wallet().get_balance().unwrap().to_string()
    }

    pub fn is_mine(&self, script: &Script) -> Result<bool, bdk::Error> {
        self.get_wallet().is_mine(&script)
    }
    #[allow(dead_code)]
    pub fn list_unspent(&self) -> Vec<LocalUtxo> {
        self.get_wallet().list_unspent().unwrap()
    }
    pub fn sync(&self, client: &EsploraClient) {
        self.get_wallet().sync(&client.0, Default::default()).unwrap();
    }
    fn remove_bip32_derivation_paths(&self, psbt: &mut PartiallySignedTransaction) {
        for output in &mut psbt.outputs {
            output.bip32_derivation.clear();
        }
    }
    pub(crate) fn sign(
        &self,
        psbt: &mut PartiallySignedTransaction,
        remove: bool,
    ) -> Result<PartiallySignedTransaction, BoxError> {
        let f = psbt.to_string();
        match self.get_wallet().sign(
            psbt,
            SignOptions { try_finalize: true, trust_witness_utxo: true, ..Default::default() },
        ) {
            Ok(e) => {
                println!("PSBT is_finalized: {}", e);
                if remove {
                    self.remove_bip32_derivation_paths(psbt);
                }

                let g = psbt.to_string();
                assert_ne!(f, g);
                return Ok((*psbt).clone());
            }
            Err(e) => panic!("{}", e.to_string()),
        }
    }
}
fn get_sender_descriptor() -> String {
    "wpkh(tprv8ZgxMBicQKsPfNH1PykMg16TAvrZgoxDnxr3eorcbhvZxyZzStwFkvqCJegr8Gbwj3GQum8QpXQPh7DGkoobpTB7YbcnUeUSKRDyX2cNN9h/84'/1'/0'/0/*)#ey7hlgpn".to_string()
}
fn get_receiver_descriptor() -> String {
    "wpkh(tprv8ZgxMBicQKsPczV7D2zfMr7oUzHDhNPEuBUgrwRoWM3ijLRvhG87xYiqh9JFLPqojuhmqwMdo1oJzbe5GUpxCbDHnqyGhQa5Jg1Wt6rc9di/84'/1'/0'/0/*)#kdnuw5lq".to_string()
}
#[allow(dead_code)]
fn extract_pj_tx(sender_wallet: &Wallet, psbt: &str) -> Result<Transaction, BoxError> {
    let mut psbt: PartiallySignedTransaction =
        PartiallySignedTransaction::from_str(psbt).expect("Invalid psbt");
    println!("Sender's Payjoin PSBT1: {:#?}", psbt.to_string());
    let f = psbt.to_string();
    let signed_psbt = sender_wallet.sign(&mut psbt, false)?;
    let g = signed_psbt.to_string();
    assert_ne!(f, g);
    println!("Sender's Payjoin PSBT: {:#?}", signed_psbt.to_string());
    Ok(signed_psbt.extract_tx())
}

#[allow(dead_code)]
fn handle_proposal(proposal: UncheckedProposal, receiver: Wallet) -> Arc<PayjoinProposal> {
    let receiver = Arc::new(receiver);
    // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
    let _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast();

    // Receive Check 1: Can Broadcast
    let proposal = proposal
        .check_broadcast_suitability(None, |_| Ok(true))
        .expect("Payjoin proposal should be broadcastable");

    // Receive Check 2: receiver can't sign for proposal inputs
    let proposal = proposal
        .check_inputs_not_owned(|e| {
            receiver
                .is_mine(Script::from_bytes(e.as_slice()))
                .map_err(|x| PayjoinError::UnexpectedError { message: x.to_string() })
        })
        .expect("Receiver should not own any of the inputs");

    // Receive Check 3: receiver can't sign for proposal inputs
    let proposal = proposal.check_no_mixed_input_scripts().unwrap();

    // Receive Check 4: have we seen this input before? More of a check for non-interactive i.e. payment processor receivers.
    let payjoin = proposal
        .check_no_inputs_seen_before(|_| Ok(false))
        .unwrap()
        .identify_receiver_outputs(|e| {
            receiver
                .is_mine(Script::from_bytes(e.as_slice()))
                .map_err(|x| PayjoinError::UnexpectedError { message: x.to_string() })
        })
        .expect("Receiver should have at least one output");

    // Select receiver payjoin inputs. TODO Lock them.
    let available_inputs = receiver.list_unspent();
    let candidate_inputs: HashMap<u64, OutPoint> = available_inputs
        .iter()
        .map(|i| {
            (i.txout.value, OutPoint { txid: i.outpoint.txid.to_string(), vout: i.outpoint.vout })
        })
        .collect();
    let selected_outpoint = payjoin.try_preserving_privacy(candidate_inputs).expect("gg");
    let selected_utxo = available_inputs
        .iter()
        .find(|i| {
            i.outpoint.txid.to_string() == selected_outpoint.txid
                && i.outpoint.vout == selected_outpoint.vout
        })
        .unwrap();

    //  calculate receiver payjoin outputs given receiver payjoin inputs and original_psbt,
    let txo_to_contribute = TxOut {
        value: selected_utxo.txout.value,
        script_pubkey: selected_utxo.txout.script_pubkey.clone().into_bytes(),
    };
    let outpoint_to_contribute = OutPoint {
        txid: selected_utxo.outpoint.txid.to_string(),
        vout: selected_utxo.outpoint.vout,
    };
    payjoin
        .contribute_witness_input(txo_to_contribute, outpoint_to_contribute)
        .expect("contribute_witness_input error");

    let payjoin_proposal = payjoin
        .finalize_proposal(
            |e| {
                match receiver
                    .sign(&mut PartiallySignedTransaction::from_str(&*e.as_str()).unwrap(), true)
                {
                    Ok(e) => Ok(e.to_string()),
                    Err(e) => Err(PayjoinError::UnexpectedError { message: e.to_string() }),
                }
            },
            Some(10),
        )
        .expect("finalize error");
    payjoin_proposal
}

#[allow(dead_code)]
fn handle_pj_request(req: Request, headers: Headers, receiver: Wallet) -> String {
    let proposal = UncheckedProposal::from_request(
        req.body,
        req.url.query().unwrap_or("".to_string()),
        Arc::new(headers),
    )
    .unwrap();
    let proposal = handle_proposal(proposal, receiver);

    let psbt = proposal.psbt();
    psbt
}
fn build_original_psbt(
    sender_wallet: &Wallet,
    pj_uri: &PjUri,
) -> Result<PartiallySignedTransaction, BoxError> {
    let wallet_mutex = sender_wallet.get_wallet();
    let mut builder = wallet_mutex.build_tx();
    let script = bdk::bitcoin::Address::from_str(pj_uri.address().as_str())?
        .assume_checked()
        .script_pubkey();
    builder
        .fee_rate(FeeRate::from_sat_per_kwu(2000.0))
        .add_recipient(script, (pj_uri.amount().unwrap() * 100000000.0) as u64)
        .fee_rate(FeeRate::from_sat_per_vb(5.0))
        .only_witness_utxo();
    let (mut psbt, _) = builder.finish()?;
    wallet_mutex
        .sign(
            &mut psbt,
            SignOptions { trust_witness_utxo: true, try_finalize: true, ..Default::default() },
        )
        .unwrap();
    sender_wallet.remove_bip32_derivation_paths(&mut psbt);
    Ok(psbt)
}
mod v1 {
    use bdk::wallet::AddressIndex;
    use payjoin_ffi::send::v1::RequestBuilder;

    use super::*;

    const EXAMPLE_URL: &str = "https://example.com";

    #[test]
    fn v1_to_v1_full_cycle() -> Result<(), BoxError> {
        let (sender, receiver, _) = init_sender_receiver_wallet();
        let _esplora_client = restore_esplora_client();

        let pj_receiver_address = receiver.get_address(AddressIndex::New);

        let pj_uri = build_pj_uri(pj_receiver_address.to_qr_uri(), 500000, EXAMPLE_URL, None)
            .unwrap()
            .check_pj_supported()
            .unwrap();
        let psbt = build_original_psbt(&sender, &pj_uri)?;
        println!("\nOriginal sender psbt: {:#?}", psbt.to_string());

        let req_ctx = RequestBuilder::from_psbt_and_uri(psbt.to_string(), pj_uri)?
            .build_with_additional_fee(10000, None, 0, false)?
            .extract_v1()?;
        let headers = Headers::from_vec(req_ctx.request.body.clone());
        let response = handle_pj_request(req_ctx.request, headers, receiver);
        println!("\nOriginal receiver psbt: {:#?}", response);
        let checked_payjoin_proposal_psbt = req_ctx
            .context_v1
            .process_response(response.as_bytes().to_vec())
            .expect("process res error");
        let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt.as_str())?;
        _esplora_client.broadcast(payjoin_tx.clone()).expect("Broadcast error");
        println!("Broadcast success: {}", payjoin_tx.txid().to_string());
        Ok(())
    }
}

mod v2 {
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;

    use bdk::bitcoin::psbt::PartiallySignedTransaction;
    use bdk::bitcoin::{Address, Script};
    use bdk::wallet::AddressIndex;
    use http::StatusCode;
    use payjoin_ffi::error::PayjoinError;
    use payjoin_ffi::receive::v2::{
        ActiveSession, SessionInitializer, V2PayjoinProposal, V2UncheckedProposal,
    };
    use payjoin_ffi::send::v1::RequestBuilder;
    use payjoin_ffi::types::{Network, OhttpKeys, OutPoint, TxOut};
    use payjoin_ffi::uri::{Uri, Url};
    use reqwest::{Client, ClientBuilder};
    use testcontainers::clients::Cli;
    use testcontainers_modules::redis::Redis;

    use crate::{
        broadcast_tx, build_original_psbt, extract_pj_tx, init_sender_receiver_wallet,
        restore_esplora_client, BoxError, Wallet,
    };
    #[tokio::test]

    async fn v2_to_v2_full_cycle() {
        let (cert, key) = local_cert_key();
        let ohttp_relay_port = find_free_port();
        let ohttp_relay = Url::from_str(format!("http://localhost:{}", ohttp_relay_port)).unwrap();
        let directory_port = find_free_port();
        let directory = Url::from_str(format!("https://localhost:{}", directory_port)).unwrap();
        let gateway_origin = http::Uri::from_str(directory.as_string().as_str()).unwrap();
        tokio::select!(
        _ = ohttp_relay::listen_tcp(ohttp_relay_port, gateway_origin) => assert!(false, "Ohttp relay is long running"),
        _ = init_directory(directory_port, (cert.clone(), key)) => assert!(false, "Directory server is long running"),
        res = do_v2_send_receive(ohttp_relay, directory, cert) => assert!(res.is_ok(), "v2 send receive failed: {:#?}", res)
        );

        async fn do_v2_send_receive(
            ohttp_relay: Url,
            directory: Url,
            cert_der: Vec<u8>,
        ) -> Result<(), BoxError> {
            let (sender, receiver, _) = init_sender_receiver_wallet();
            let esplora_client = restore_esplora_client();
            let agent = Arc::new(http_agent(cert_der.clone()).unwrap());
            wait_for_service_ready(ohttp_relay.clone(), agent.clone()).await?;
            wait_for_service_ready(directory.clone(), agent.clone()).await?;
            let ohttp_keys =
                payjoin_ffi::io::fetch_ohttp_keys(ohttp_relay, directory.clone(), cert_der.clone())
                    .await?;
            let address = receiver.get_address(AddressIndex::New);
            // test session with expiry in the future
            let session = initialize_session(
                address.clone(),
                directory.clone(),
                ohttp_keys.clone(),
                cert_der.clone(),
                None,
            )
            .await?;
            let pj_uri_string = session.pj_uri_builder().amount(5000000).build().as_string();
            // Poll receive request
            let (req, ctx) = session.extract_req()?;
            let response = agent.post(req.url.as_string()).body(req.body).send().await?;
            assert!(response.status().is_success());
            let response_body = session.process_res(response.bytes().await?.to_vec(), ctx).unwrap();
            // No proposal yet since sender has not responded
            assert!(response_body.is_none());
            let pj_uri = Uri::from_str(pj_uri_string).unwrap().check_pj_supported().unwrap();
            let psbt = build_original_psbt(&sender, &pj_uri)?;
            println!("\nOriginal sender psbt: {:#?}", psbt.to_string());

            let req_ctx = RequestBuilder::from_psbt_and_uri(psbt.to_string(), pj_uri)?
                .build_recommended(payjoin::bitcoin::FeeRate::BROADCAST_MIN.to_sat_per_kwu())?;
            let req_ctx_v2 = req_ctx.extract_v2(Arc::new(directory.to_owned()))?;
            let response = agent
                .post(req_ctx_v2.request.url.as_string())
                .header("Content-Type", payjoin::V1_REQ_CONTENT_TYPE)
                .body(req_ctx_v2.request.body.clone())
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
            let response_body =
                req_ctx_v2.context_v2.process_response(response.bytes().await?.to_vec())?;
            // No response body yet since we are async and pushed fallback_psbt to the buffer
            assert!(response_body.is_none());
            // **********************
            // Inside the Receiver:

            // GET fallback psbt
            let (req, ctx) = session.extract_req()?;
            let response = agent.post(req.url.as_string()).body(req.body).send().await?;
            let proposal = session.process_res(response.bytes().await?.to_vec(), ctx)?.unwrap();
            let payjoin_proposal = handle_directory_proposal(receiver, proposal);
            assert!(!payjoin_proposal.is_output_substitution_disabled());
            let (req, ctx) = payjoin_proposal.extract_v2_req()?;
            let response = agent.post(req.url.as_string()).body(req.body).send().await?;
            let res = response.bytes().await?.to_vec();
            payjoin_proposal.process_res(res, ctx)?;
            let req_ctx_v2 = req_ctx.extract_v2(Arc::new(directory.to_owned()))?;
            let response = agent
                .post(req_ctx_v2.request.url.as_string())
                .body(req_ctx_v2.request.body)
                .send()
                .await?;
            let checked_payjoin_proposal_psbt =
                req_ctx_v2.context_v2.process_response(response.bytes().await?.to_vec())?.unwrap();
            let payjoin_tx = extract_pj_tx(&sender, checked_payjoin_proposal_psbt.as_str())?;
            broadcast_tx(esplora_client, payjoin_tx).unwrap();
            Ok(())
        }
    }
    async fn initialize_session(
        address: Address,
        directory: Url,
        ohttp_keys: OhttpKeys,
        cert_der: Vec<u8>,
        custom_expire_after: Option<u64>,
    ) -> Result<ActiveSession, BoxError> {
        let mock_ohttp_relay = directory.clone(); // pass through to
        let initializer = SessionInitializer::new(
            address.to_string(),
            custom_expire_after,
            Network::Regtest,
            directory,
            ohttp_keys,
            mock_ohttp_relay,
        )
        .unwrap();
        let (req, ctx) = initializer.extract_req()?;
        println!("enroll req: {:#?}", &req.url.as_string());
        let response =
            http_agent(cert_der).unwrap().post(req.url.as_string()).body(req.body).send().await?;
        assert!(response.status().is_success());
        Ok(initializer.process_res(response.bytes().await?.to_vec(), ctx)?)
    }
    async fn wait_for_service_ready(
        service_url: Url,
        agent: Arc<Client>,
    ) -> Result<(), &'static str> {
        let health_url = <Url as Into<url::Url>>::into(service_url)
            .join("/health")
            .map_err(|_| "Invalid URL")?;
        let start = std::time::Instant::now();

        while start.elapsed() < Duration::from_secs(20) {
            let request_result =
                agent.get(health_url.as_str()).send().await.map_err(|_| "Bad request")?;

            match request_result.status() {
                StatusCode::OK => return Ok(()),
                StatusCode::NOT_FOUND => return Err("Endpoint not found"),
                _ => std::thread::sleep(Duration::from_secs(3)),
            }
        }

        Err("Timeout waiting for service to be ready")
    }
    fn handle_directory_proposal(
        receiver: Wallet,
        proposal: V2UncheckedProposal,
    ) -> V2PayjoinProposal {
        // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
        let _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast();

        // Receive Check 1: Can Broadcast
        let proposal = proposal.assume_interactive_receiver();

        // Receive Check 2: receiver can't sign for proposal inputs
        let proposal = proposal
            .check_inputs_not_owned(|input| {
                receiver
                    .is_mine(Script::from_bytes(input))
                    .map_err(|x| PayjoinError::UnexpectedError { message: x.to_string() })
            })
            .expect("Receiver should not own any of the inputs");

        // Receive Check 3: receiver can't sign for proposal inputs
        let proposal = proposal.check_no_mixed_input_scripts().unwrap();

        // Receive Check 4: have we seen this input before? More of a check for non-interactive i.e. payment processor receivers.
        let payjoin = proposal
            .check_no_inputs_seen_before(|_| Ok(false))
            .unwrap()
            .identify_receiver_outputs(|output_script| {
                receiver
                    .is_mine(Script::from_bytes(output_script.as_slice()))
                    .map_err(|x| PayjoinError::UnexpectedError { message: x.to_string() })
            })
            .expect("Receiver should have at least one output");

        // Select receiver payjoin inputs. TODO Lock them.
        let available_inputs = receiver.list_unspent();
        let candidate_inputs: HashMap<u64, OutPoint> = available_inputs
            .iter()
            .map(|i| {
                (
                    i.txout.value,
                    OutPoint { txid: i.outpoint.txid.to_string(), vout: i.outpoint.vout },
                )
            })
            .collect();
        let selected_outpoint = payjoin
            .try_preserving_privacy(candidate_inputs)
            .expect("receiver input that avoids surveillance not found");
        let selected_utxo = available_inputs
            .iter()
            .find(|i| {
                i.outpoint.txid.to_string() == selected_outpoint.txid
                    && i.outpoint.vout == selected_outpoint.vout
            })
            .unwrap();

        //  calculate receiver payjoin outputs given receiver payjoin inputs and original_psbt,
        let txo_to_contribute = TxOut {
            value: selected_utxo.txout.value,
            script_pubkey: selected_utxo.txout.script_pubkey.clone().into_bytes(),
        };
        let outpoint_to_contribute = OutPoint {
            txid: selected_utxo.outpoint.txid.to_string(),
            vout: selected_utxo.outpoint.vout,
        };
        let _ = payjoin.contribute_witness_input(txo_to_contribute, outpoint_to_contribute);

        _ = payjoin.try_substitute_receiver_output(|| {
            Ok(receiver.get_address(AddressIndex::New).script_pubkey().into_bytes())
        });
        let payjoin_proposal = payjoin
            .finalize_proposal(
                |psbt| {
                    match receiver.sign(
                        &mut PartiallySignedTransaction::from_str(psbt.as_str()).unwrap(),
                        true,
                    ) {
                        Ok(e) => Ok(e.to_string()),
                        Err(e) => Err(PayjoinError::UnexpectedError { message: e.to_string() }),
                    }
                },
                Some(10),
            )
            .unwrap();
        (*payjoin_proposal).clone()
    }
    async fn init_directory(port: u16, local_cert_key: (Vec<u8>, Vec<u8>)) -> Result<(), BoxError> {
        let docker: Cli = Cli::default();
        let timeout = Duration::from_secs(2);
        let db = docker.run(Redis::default());
        let db_host = format!("127.0.0.1:{}", db.get_host_port_ipv4(6379));
        println!("Database running on {}", db.get_host_port_ipv4(6379));
        payjoin_directory::listen_tcp_with_tls(port, db_host, timeout, local_cert_key).await
    }
    // generates or gets a DER encoded localhost cert and key.
    fn local_cert_key() -> (Vec<u8>, Vec<u8>) {
        let cert = rcgen::generate_simple_self_signed(vec![
            "0.0.0.0".to_string(),
            "localhost".to_string(),
        ])
        .expect("Failed to generate cert");
        let cert_der = cert.serialize_der().expect("Failed to serialize cert");
        let key_der = cert.serialize_private_key_der();
        (cert_der, key_der)
    }
    fn find_free_port() -> u16 {
        let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        listener.local_addr().unwrap().port()
    }
    fn http_agent(cert_der: Vec<u8>) -> Result<Client, BoxError> {
        Ok(http_agent_builder(cert_der)?.build()?)
    }

    fn http_agent_builder(cert_der: Vec<u8>) -> Result<ClientBuilder, BoxError> {
        Ok(ClientBuilder::new()
            .danger_accept_invalid_certs(true)
            .use_rustls_tls()
            .add_root_certificate(
                reqwest::tls::Certificate::from_der(cert_der.as_slice()).unwrap(),
            ))
    }
}
