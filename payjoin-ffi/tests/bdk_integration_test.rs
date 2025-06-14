// tests/bdk_integration_test.rs

/*!
This test suite ensures the soundness of `payjoin_ffi` types. It verifies that the core functionality of these types works as expected. The `uniffi` wrappers on these types are tested at a higher level to ensure compatibility with Flutter, allowing shared FFI types to be utilized effectively.

The tests simulate a full cycle of PayJoin transactions, including wallet initialization, transaction creation, and broadcasting. They cover both v1 and v2 PayJoin protocols, ensuring that the integration with `bdk` and `bitcoind` is seamless and reliable.
*/
#![cfg(all(feature = "_danger-local-https", feature = "_test-utils", not(feature = "uniffi")))]

use std::str::FromStr;
use std::sync::{Mutex, MutexGuard};

use bdk::bitcoin::key::Secp256k1;
use bdk::bitcoin::psbt::PartiallySignedTransaction;
use bdk::bitcoin::{Address, Network, Script, Transaction};
use bdk::blockchain::{Blockchain, ConfigurableBlockchain, RpcBlockchain, RpcConfig};
use bdk::database::MemoryDatabase;
use bdk::descriptor::IntoWalletDescriptor;
use bdk::wallet::AddressIndex;
use bdk::{FeeRate, LocalUtxo, SignOptions, Wallet as BdkWallet};
use bitcoincore_rpc::RpcApi;
use payjoin_ffi::receive::{ImplementationError, InputPair};
use payjoin_ffi::uri::PjUri;

type BoxError = Box<dyn std::error::Error + 'static>;

pub struct RpcClient(RpcBlockchain);

impl RpcClient {
    pub fn new<T>(bitcoind: &bitcoind::BitcoinD, descriptor: T) -> Self
    where
        T: IntoWalletDescriptor,
    {
        let config = RpcConfig {
            url: bitcoind.rpc_url(),
            auth: bdk::blockchain::rpc::Auth::Cookie { file: bitcoind.params.cookie_file.clone() },
            network: Network::Regtest,
            wallet_name: bdk::wallet::wallet_name_from_descriptor(
                descriptor,
                None,
                Network::Regtest,
                &Secp256k1::new(),
            )
            .unwrap(),
            sync_params: Default::default(),
        };
        let client = RpcBlockchain::from_config(&config).unwrap();
        Self(client)
    }

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

fn restore_rpc_client(bitcoind: &bitcoind::BitcoinD, descriptor: &str) -> RpcClient {
    RpcClient::new(bitcoind, descriptor)
}

fn init_sender_receiver_wallet() -> (Wallet, Wallet, bitcoind::BitcoinD) {
    let sender = restore_wallet(get_sender_descriptor()).expect("Wallet::new failed");
    let receiver = restore_wallet(get_receiver_descriptor()).expect("Wallet::new failed");
    let bitcoind_exe = std::env::var("BITCOIND_EXE")
        .ok()
        .or_else(|| bitcoind::downloaded_exe_path().ok())
        .unwrap();
    let conf = bitcoind::Conf::default();
    let bitcoind = bitcoind::BitcoinD::with_conf(bitcoind_exe, &conf)
        .expect("bitcoind::BitcoinD::with_conf failed");
    let sender_bdk_rpc_client = restore_rpc_client(&bitcoind, &get_sender_descriptor());
    let receiver_bdk_rpc_client = restore_rpc_client(&bitcoind, &get_receiver_descriptor());
    let receiver_address_bdk = receiver.get_address(AddressIndex::New);
    let sender_address_bdk = sender.get_address(AddressIndex::New);
    let receiver_address_bitcoind =
        bitcoincore_rpc::bitcoin::address::Address::from_str(&*receiver_address_bdk.to_string())
            .unwrap()
            .assume_checked();
    let sender_address_bitcoind =
        bitcoincore_rpc::bitcoin::address::Address::from_str(&*sender_address_bdk.to_string())
            .unwrap()
            .assume_checked();
    let sender_balance = sender.get_balance().to_string();
    let receiver_balance = receiver.get_balance().to_string();

    bitcoind.client.generate_to_address(1, &receiver_address_bitcoind).unwrap();
    bitcoind.client.generate_to_address(101, &sender_address_bitcoind).unwrap();
    let _ = sender.sync(&sender_bdk_rpc_client);
    let _ = receiver.sync(&receiver_bdk_rpc_client);
    println!("\n Sender balance: {:?}", receiver.get_balance());
    println!("\n Receiver balance: {:?}", sender.get_balance());
    assert_ne!(receiver_balance, receiver.get_balance(), "receiver doesn't own bitcoin");

    assert_ne!(sender_balance, sender.get_balance(), "sender doesn't own bitcoin");
    (sender, receiver, bitcoind)
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

    pub fn get_balance(&self) -> String { self.get_wallet().get_balance().unwrap().to_string() }

    pub fn is_mine(&self, script: &Script) -> Result<bool, bdk::Error> {
        self.get_wallet().is_mine(&script)
    }

    pub fn list_unspent(&self) -> Vec<LocalUtxo> { self.get_wallet().list_unspent().unwrap() }
    pub fn sync(&self, client: &RpcClient) {
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

fn build_original_psbt(
    sender_wallet: &Wallet,
    pj_uri: &PjUri,
) -> Result<PartiallySignedTransaction, BoxError> {
    let wallet_mutex = sender_wallet.get_wallet();
    let mut builder = wallet_mutex.build_tx();
    dbg!("building original psbt");
    let script = bdk::bitcoin::Address::from_str(pj_uri.address().as_str())?
        .assume_checked()
        .script_pubkey();
    dbg!("adding recipient");
    builder
        .fee_rate(FeeRate::from_sat_per_kwu(2000.0))
        .add_recipient(script, pj_uri.amount_sats().unwrap_or(100_000_000))
        .fee_rate(FeeRate::from_sat_per_vb(5.0))
        .only_witness_utxo();
    dbg!("finishing");
    let (mut psbt, _) = builder.finish()?;
    dbg!("signing");
    wallet_mutex
        .sign(
            &mut psbt,
            SignOptions { trust_witness_utxo: true, try_finalize: true, ..Default::default() },
        )
        .unwrap();
    dbg!("removing bip32 derivation paths");
    sender_wallet.remove_bip32_derivation_paths(&mut psbt);
    Ok(psbt)
}

#[cfg(feature = "_danger-local-https")]
mod v2 {
    use std::sync::Arc;

    use bdk::wallet::AddressIndex;
    use bitcoin_ffi::{Address, Network};
    use payjoin_ffi::receive::{PayjoinProposal, UncheckedProposal, UninitializedReceiver};
    use payjoin_ffi::send::SenderBuilder;
    use payjoin_ffi::uri::Uri;
    use payjoin_ffi::{NoopSessionPersister, Request};
    use payjoin_test_utils::TestServices;

    use super::*;
    use crate::{
        build_original_psbt, extract_pj_tx, get_sender_descriptor, init_sender_receiver_wallet,
        input_pair_from_local_utxo, restore_rpc_client, BoxError, Wallet,
    };

    #[tokio::test]
    async fn v2_to_v2_full_cycle() {
        let mut services = TestServices::initialize().await.unwrap();
        tokio::select!(
        _ = services.take_ohttp_relay_handle()  => assert!(false, "Ohttp relay is long running"),
        _ = services.take_directory_handle()  => assert!(false, "Directory server is long running"),
        res = do_v2_send_receive(&services) => assert!(res.is_ok(), "v2 send receive failed: {:#?}", res)
        );

        async fn do_v2_send_receive(services: &TestServices) -> Result<(), BoxError> {
            let (sender, receiver, bitcoind) = init_sender_receiver_wallet();
            let blockchain_client = restore_rpc_client(&bitcoind, &get_sender_descriptor());
            let agent = services.http_agent();
            let directory = services.directory_url();
            services.wait_for_services_ready().await?;
            let ohttp_keys = payjoin_ffi::io::fetch_ohttp_keys_with_cert(
                services.ohttp_relay_url().as_str(),
                directory.as_str(),
                services.cert(),
            )
            .await?;

            let address = receiver.get_address(AddressIndex::New);
            let recv_session_persister = NoopSessionPersister::default();
            let sender_session_persister = NoopSessionPersister::default();
            let session = UninitializedReceiver::create_session(
                Address::new(address.to_string(), Network::Regtest).unwrap(),
                directory.to_string(),
                ohttp_keys,
                None,
            )
            .save(&recv_session_persister)?;
            let ohttp_relay = services.ohttp_relay_url();
            // Poll receive request
            let (request, client_response) = session.extract_req(ohttp_relay.to_string())?;
            let response = agent
                .post(request.url.as_string())
                .header("Content-Type", request.content_type)
                .body(request.body)
                .send()
                .await?;
            assert!(response.status().is_success());
            let response_body = session
                .process_res(&response.bytes().await?, &client_response)
                .save(&recv_session_persister)
                .unwrap();
            // No proposal yet since sender has not responded
            assert!(response_body.is_none());

            // **********************
            // Inside the Sender:
            // Create a funded PSBT (not broadcasted) to address with amount given in the pj_uri
            let pj_uri =
                Uri::parse(session.pj_uri().as_string()).unwrap().check_pj_supported().unwrap();
            let psbt = build_original_psbt(&sender, &pj_uri)?;
            println!("\nOriginal sender psbt: {:#?}", psbt.to_string());

            let req_ctx = SenderBuilder::new(psbt.to_string(), pj_uri)?
                .build_recommended(payjoin::bitcoin::FeeRate::BROADCAST_MIN.to_sat_per_kwu())
                .save(&sender_session_persister)?;
            let (request, context) = req_ctx.extract_v2(ohttp_relay.to_owned().into())?;
            let response = agent
                .post(request.url.as_string())
                .header("Content-Type", request.content_type)
                .body(request.body.clone())
                .send()
                .await
                .unwrap();
            assert!(response.status().is_success());
            let send_ctx = req_ctx
                .process_response(&response.bytes().await?, context)
                .save(&sender_session_persister)?;

            // **********************
            // Inside the Receiver:

            // GET fallback psbt
            let (request, client_response) = session.extract_req(ohttp_relay.to_string())?;
            let response = agent
                .post(request.url.as_string())
                .header("Content-Type", request.content_type)
                .body(request.body)
                .send()
                .await?;
            let proposal = session
                .process_res(&response.bytes().await?, &client_response)
                .save(&recv_session_persister)?
                .success()
                .expect("proposal should exist");
            let payjoin_proposal = handle_directory_proposal(receiver, proposal);
            let (request, client_response) =
                payjoin_proposal.extract_req(ohttp_relay.to_string())?;
            let response = agent
                .post(request.url.as_string())
                .header("Content-Type", request.content_type)
                .body(request.body)
                .send()
                .await?;
            payjoin_proposal
                .process_res(&response.bytes().await?, &client_response)
                .save(&recv_session_persister)?;

            // **********************
            // Inside the Sender:
            // Sender checks, signs, finalizes, extracts, and broadcasts
            // Replay post fallback to get the response
            let (Request { url, body, content_type, .. }, ohttp_ctx) =
                send_ctx.extract_req(ohttp_relay.to_string())?;
            let response = agent
                .post(url.as_string())
                .header("Content-Type", content_type)
                .body(body)
                .send()
                .await?;
            let checked_payjoin_proposal_psbt = send_ctx
                .process_response(&response.bytes().await?, &ohttp_ctx)
                .save(&sender_session_persister)?
                .success()
                .unwrap();
            let payjoin_tx =
                extract_pj_tx(&sender, checked_payjoin_proposal_psbt.serialize_base64().as_str())?;
            blockchain_client.broadcast(payjoin_tx).unwrap();
            Ok(())
        }
    }

    fn handle_directory_proposal(receiver: Wallet, proposal: UncheckedProposal) -> PayjoinProposal {
        let session_persister = NoopSessionPersister::default();
        // Receive Check 1: Can Broadcast
        let proposal = proposal
            .assume_interactive_receiver()
            .save(&session_persister)
            .expect("Noop Persister should not fail");
        let receiver = Arc::new(receiver);
        // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
        let _to_broadcast_in_failure_case = proposal.extract_tx_to_schedule_broadcast();

        // Receive Check 2: receiver can't sign for proposal inputs
        let proposal = proposal
            .check_inputs_not_owned(|script| is_script_owned(&receiver, script.clone()))
            .save(&session_persister)
            .expect("Receiver should not own any of the inputs");

        // Receive Check 3: have we seen this input before? More of a check for non-interactive i.e. payment processor receivers.
        let wants_outputs = proposal
            .check_no_inputs_seen_before(|outpoint| mock_is_output_known(outpoint.clone()))
            .save(&session_persister)
            .unwrap()
            .identify_receiver_outputs(|script| is_script_owned(&receiver, script.clone()))
            .save(&session_persister)
            .expect("Receiver should have at least one output");
        _ = wants_outputs.substitute_receiver_script(&bitcoin_ffi::Script::new(
            receiver.get_address(AddressIndex::New).script_pubkey().into_bytes(),
        ));
        let wants_inputs = wants_outputs
            .commit_outputs()
            .save(&session_persister)
            .expect("Noop Persister should not fail");
        // Select receiver payjoin inputs. TODO Lock them.
        let available_inputs = receiver
            .list_unspent()
            .into_iter()
            .map(input_pair_from_local_utxo)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let selected_outpoint = wants_inputs
            .try_preserving_privacy(available_inputs)
            .expect("receiver input that avoids surveillance not found");

        let provisional_proposal = wants_inputs
            .contribute_inputs(vec![selected_outpoint])
            .unwrap()
            .commit_inputs()
            .save(&session_persister)
            .expect("Noop Persister should not fail");

        let payjoin_proposal = provisional_proposal
            .finalize_proposal(|psbt| process_psbt(&receiver, psbt), Some(10), Some(100))
            .save(&session_persister)
            .unwrap();
        payjoin_proposal
    }
}

fn input_pair_from_local_utxo(utxo: LocalUtxo) -> Result<InputPair, BoxError> {
    let psbtin = payjoin::bitcoin::psbt::Input {
        // NOTE: non_witness_utxo is not necessary because bitcoin-cli always supplies
        // witness_utxo, even for non-witness inputs
        witness_utxo: Some(payjoin::bitcoin::TxOut {
            value: payjoin::bitcoin::Amount::from_sat(utxo.txout.value),
            script_pubkey: payjoin::bitcoin::Script::from_bytes(
                utxo.txout.script_pubkey.as_bytes(),
            )
            .into(),
        }),
        redeem_script: None,  // utxo.redeem_script.clone(),
        witness_script: None, // utxo.witness_script.clone(),
        ..Default::default()
    };
    let txin = payjoin::bitcoin::TxIn {
        previous_output: payjoin::bitcoin::OutPoint::from_str(&utxo.outpoint.to_string()).unwrap(),
        ..Default::default()
    };
    InputPair::new(txin.clone().into(), psbtin.clone().into(), None)
        .map_err(|e| format!("Failed to create input pair: {:?}", e).into())
}

fn is_script_owned(wallet: &Wallet, script: Vec<u8>) -> Result<bool, ImplementationError> {
    wallet.is_mine(Script::from_bytes(script.as_slice())).map_err(|e| e.to_string().into())
}

fn mock_is_output_known(_: bitcoin_ffi::OutPoint) -> Result<bool, ImplementationError> { Ok(false) }

fn process_psbt(wallet: &Wallet, psbt: String) -> Result<String, ImplementationError> {
    wallet
        .sign(&mut PartiallySignedTransaction::from_str(&psbt).unwrap(), true)
        .map(|e| e.to_string())
        .map_err(|e| e.to_string().into())
}
