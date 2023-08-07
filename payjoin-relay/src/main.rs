use tokio::net::TcpListener;
use std::sync::Arc;
use hyper::Body;
use hyper::service::{make_service_fn, service_fn};
use hyper::StatusCode;
use tokio::sync::{mpsc, Mutex};
use tungstenite::Message;
use futures_util::{SinkExt, StreamExt};

use payjoin::relay;

#[tokio::main]
async fn main() {
    let server = TcpListener::bind("127.0.0.1:3012").await.unwrap();
    println!("REElay listening on ws://127.0.0.1:3012 😡");
    let req_buffer = Buffer::new();
    let res_buffer = Buffer::new();
    
    let ws_req_buffer = req_buffer.clone();
    let ws_res_buffer = res_buffer.clone();
    tokio::spawn(async move {
        // run websocket server. On connection, await Original PSBT, relay to http server
        while let Ok((stream, _)) = server.accept().await {
            println!("New ws connection!");
            let ws_req_buffer = ws_req_buffer.clone();
            let ws_res_buffer = ws_res_buffer.clone();
            tokio::spawn(async move {
                let ws_stream = tokio_tungstenite::accept_async(stream).await.unwrap();
                let (mut write, mut read) = ws_stream.split();
                let msg = read.next().await.unwrap().unwrap();
                println!("Received: {}, awaiting Original PSBT", msg);
                if msg.to_text().unwrap() == "receiver" {
                    let buffered_req = ws_req_buffer.clone().peek().await;
                    // relay Original PSBT request to receiver via websocket
                    let post = Message::Text(buffered_req.to_string());
                    println!("Received Original PSBT, relaying to receiver via websocket");
                    write.send(post).await.unwrap();
        
                    println!("Awaiting Payjoin PSBT from receiver via websocket"); // does this need to be async? break because block?
                    // TODO await ws client transform Original PSBT into Payjoin PSBT
                    let msg = read.next().await.unwrap().unwrap();
                    let serialized_res =  msg.into_text().unwrap();
                    println!("Received Payjoin PSBT res {:#?}, relaying to sender via http", serialized_res);
        
                    ws_res_buffer.push(serialized_res).await;
                    println!("sent to http server via push");
                }
            });
        }
    });
   
    // run HTTP server. On Post PJ, relay to websocket
    let make_svc = make_service_fn(move |_| {
        let req_buffer = req_buffer.clone();
        let res_buffer = res_buffer.clone();
        async move {
            let handler = move |req| handle_http_req(req_buffer.clone(), res_buffer.clone(), req);
            Ok::<_, hyper::Error>(service_fn(handler))
        }
    });

    let server = hyper::Server::bind(&([127, 0, 0, 1], 3000).into()).serve(make_svc);
    println!("REElay configured to listen on http://127.0.0.1:3000 😡");
    server.await.unwrap();
}

async fn handle_http_req(
    req_buffer: Buffer,
    res_buffer: Buffer,
    req: hyper::Request<Body>,
) -> Result<hyper::Response<Body>, hyper::Error> {

    match (req.method().clone(), req.uri().path()) {
        (hyper::Method::POST, "/") => {
            println!("POST / <Original PSBT> received");
            let header = req.headers().clone();
            let query = req.uri().query().unwrap_or("").to_string();
            let body = hyper::body::to_bytes(req.into_body()).await?.to_vec();
            println!("POST / <Original PSBT> body: {:?}", body);
            let relay_req = relay::Request { headers: header, query, body };
            let serialized_req = serde_json::to_string(&relay_req).unwrap();
            req_buffer.push(serialized_req).await;
            println!("Relayed req to ws channel from HTTP, awaiting Response");

            let serialized_res = res_buffer.peek().await;
            let res = serde_json::from_str::<relay::Response>(&serialized_res).unwrap();
            println!("POST / response <Payjoin PSBT> received {:?}", res);
            let res = hyper::Response::builder()
                .status(StatusCode::from_u16(res.status_code).unwrap())
                .body(Body::from(res.body))
                .unwrap();
            Ok::<hyper::Response<Body>, hyper::Error>(res)
        },
        _ => {
            let mut not_found = hyper::Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

pub(crate) struct Buffer {
    buffer: Arc<Mutex<String>>,
    sender: mpsc::Sender<()>,
    receiver: Arc<Mutex<mpsc::Receiver<()>>>,
}

/// Clone here makes a copy of the Arc pointer, not the underlying data
/// All clones point to the same internal data
impl Clone for Buffer {
    fn clone(&self) -> Self {
        Buffer {
            buffer: Arc::clone(&self.buffer),
            sender: self.sender.clone(),
            receiver: Arc::clone(&self.receiver),
        }
    }
}

impl Buffer {
    fn new() -> Self {
        let (sender, receiver) = mpsc::channel(1);
        Buffer {
            buffer: Arc::new(Mutex::new(String::new())),
            sender,
            receiver: Arc::new(Mutex::new(receiver)),
        }
    }

    async fn push(&self, request: String) {
        let mut buffer: tokio::sync::MutexGuard<'_, String> = self.buffer.lock().await;
        *buffer = request;
        let _ = self.sender.send(()).await; // signal that a new request has been added
    }

    async fn peek(&self) -> String {
        let mut buffer = self.buffer.lock().await;
        let mut contents = buffer.clone();
        if contents.is_empty() {
            drop(buffer);
            // wait for a signal that a new request has been added
            self.receiver.lock().await.recv().await;
            buffer = self.buffer.lock().await;
            contents = buffer.clone();
        }
        contents
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;

    use super::*;
    use bitcoind::bitcoincore_rpc;
    use env_logger;

    use bitcoin::psbt::Psbt;
    use bitcoin::{Amount, OutPoint};
    use bitcoind::bitcoincore_rpc::Client;
    use bitcoind::bitcoincore_rpc::core_rpc_json::AddressType;
    use bitcoind::bitcoincore_rpc::RpcApi;
    use log::{log_enabled, Level};
    use payjoin::bitcoin::base64;
    use payjoin::receive::Error;
    use payjoin::{bitcoin, PjUriExt, UriExt};

    #[tokio::test]
    async fn test_buffer() {
        let buffer = Buffer::new();
        let buffer_clone = buffer.clone();
        tokio::spawn(async move {
            buffer_clone.push("test".to_string()).await;
        });
        buffer.peek().await;
    }

    #[tokio::test]
    async fn test_concurrent_payjoin() {
        let _ = env_logger::try_init();
        // Set up sender & receiver bitcoind wallets
        let bitcoind_exe = std::env::var("BITCOIND_EXE")
            .ok()
            .or_else(|| bitcoind::downloaded_exe_path().ok())
            .expect("version feature or env BITCOIND_EXE is required for tests");
        let mut conf = bitcoind::Conf::default();
        conf.view_stdout = log_enabled!(Level::Debug);
        let bitcoind = bitcoind::BitcoinD::with_conf(bitcoind_exe, &conf).unwrap();
        let receiver = bitcoind.create_wallet("receiver").unwrap();
        let receiver_address =
            receiver.get_new_address(None, Some(AddressType::Bech32)).unwrap().assume_checked();
        let sender = bitcoind.create_wallet("sender").unwrap();
        let sender_address =
            sender.get_new_address(None, Some(AddressType::Bech32)).unwrap().assume_checked();
        bitcoind.client.generate_to_address(1, &receiver_address).unwrap();
        bitcoind.client.generate_to_address(101, &sender_address).unwrap();

        // # 1. set up relay
        let relay = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let relay_addr = relay.local_addr().expect("could not get server address");
        println!("Relay listening on ws://{}", &relay_addr);
        let req_buffer = Buffer::new();
        let res_buffer = Buffer::new();
        
        let ws_req_buffer = req_buffer.clone();
        let ws_res_buffer = res_buffer.clone();
        let _relay_thread = tokio::spawn(async move {
            // run websocket server. On connection, await Original PSBT, relay to http server
            println!("starting websocket server");
            while let Ok((stream, _)) = relay.accept().await {
                println!("New ws connection!");
                let ws_req_buffer = ws_req_buffer.clone();
                let ws_res_buffer = ws_res_buffer.clone();
                tokio::spawn(async move {
                    let ws_stream = tokio_tungstenite::accept_async(stream).await.unwrap();
                    let (mut write, mut read) = ws_stream.split();
                    let msg = read.next().await.unwrap().unwrap();
                    println!("Received: {}, awaiting Original PSBT", msg);

                    if msg.to_text().unwrap() == "receiver" {
                        let buffered_req = ws_req_buffer.clone().peek().await;
                        // relay Original PSBT request to receiver via websocket
                        let post = Message::Text(buffered_req.to_string());
                        println!("Received Original PSBT, relaying to receiver via websocket");
                        write.send(post).await.unwrap();
            
                        println!("Awaiting Payjoin PSBT from receiver via websocket");
                        match read.next().await {
                            Some(Ok(Message::Text(res))) => {
                                println!("Received Payjoin PSBT res {:#?}, relaying to sender via http", res);
                                
                                ws_res_buffer.push(res).await;
                                println!("sent to http server via push");
                            },
                            // close frame or other unexpected response
                            _ => return,
                        }
                    } else {
                        println!("Received sender request");
                        let serialized_req = msg.into_text().unwrap();
                        ws_req_buffer.push(serialized_req).await;

                        println!("Awaiting response");
                        let serialized_res = ws_res_buffer.peek().await;
                        write.send(Message::Text(serialized_res)).await.unwrap();
                        println!("Response returned to sender via websocket");
                    }
                });
            }
        });

        // receiver
        let request_address = receiver.get_new_address(None, Some(AddressType::Bech32)).unwrap().
        assume_checked();
        let request_amount = Amount::from_sat(69420);
        let request_mock_pj = "https://localhost:3000".parse::<url::Url>().unwrap();
        let uri = format!("bitcoin:{}?amount={}&pj={}", request_address, request_amount.display_in(bitcoin::amount::Denomination::Bitcoin), request_mock_pj);
        let uri = payjoin::Uri::try_from(uri).expect("Failed to create URI from string").assume_checked();
        let uri = uri.check_pj_supported().expect("The provided URI doesn't support Payjoin");

        let receive_thread = tokio::spawn(async move {
            println!("Await relay boot");
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            println!("receiver thread started");
            let ws_url = format!("ws://{}/socket", &relay_addr);
            println!("Enrolling receiver with relay @ {}", &ws_url);
            let (mut ws_stream, _) = tokio_tungstenite::connect_async(ws_url.clone()).await.expect("Can't connect");
            println!("receiver connected");
            ws_stream.send(Message::Text("receiver".to_string())).await.unwrap();
            println!("receiver sent enrollment");
            ws_stream.close(None).await.unwrap();
            println!("receiver closed connection");
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            let (mut ws_stream, _) = tokio_tungstenite::connect_async(ws_url.clone()).await.expect("Can't connect");
            ws_stream.send(Message::Text("receiver".to_string())).await.unwrap();
            println!("receiver reconnected");
            let msg = ws_stream.next().await.expect("Error reading message").unwrap();
            let req: relay::Request = serde_json::from_str(&msg.to_text().unwrap()).unwrap();
            let body = std::io::Cursor::new(req.body);
            let raw_res_body = handle_payjoin_req(receiver, body, &req.query, req.headers).unwrap();
            ws_stream.send(Message::text(raw_res_body)).await.unwrap();
        });

        // 2. set up sender, receiver bitcoind wallets
        let sender_thread = tokio::spawn(async move {
            println!("Await receiver relay enrollment");
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            println!("sender thread started");
            let ws_url = format!("ws://{}/socket", &relay_addr);
            let (mut ws_stream, _) = tokio_tungstenite::connect_async(ws_url.clone()).await.expect("Can't connect");
            // TODO check that mailbox exists on relay
            let mut outputs = HashMap::with_capacity(1);
            outputs.insert(request_address.to_string(), request_amount);
            let options = bitcoincore_rpc::json::WalletCreateFundedPsbtOptions {
                lock_unspent: Some(true),
                fee_rate: Some(Amount::from_sat(2000)), // sat_per_kwu
                ..Default::default()
            };
            let psbt = sender
                .wallet_create_funded_psbt(
                    &[], // inputs
                    &outputs,
                    None, // locktime
                    Some(options),
                    None,
                )
                .expect("Failed to create PSBT")
                .psbt;
            let psbt = sender
                .wallet_process_psbt(&psbt, None, None, None)
                .expect("Failed to process PSBT")
                .psbt;
            let psbt = Psbt::from_str(&psbt).expect("Failed to load PSBT from base64");
            println!("Original psbt: {:#?}", psbt);
            let pj_params = payjoin::send::Configuration::with_fee_contribution(
                payjoin::bitcoin::Amount::from_sat(10000),
                None,
            );
            let (req, ctx) = uri
                .create_pj_request(psbt, pj_params)
                .expect("Failed to create payjoin request");
            println!("Sending payjoin request body: {:#?}", req.body);
            let mut headers = hyper::HeaderMap::new();
            headers.append("Content-Type", hyper::header::HeaderValue::from_str("text/plain").unwrap());
            headers.append("Content-Length", hyper::header::HeaderValue::from_str(&req.body.len().to_string()).unwrap());
            let serialized_req = serde_json::to_string(&relay::Request {
                query: req.url.query().unwrap_or("").to_string(),
                headers,
                body: req.body,
            }).expect("Serialized Request");
            ws_stream.send(Message::Text(serialized_req)).await.unwrap();
            let msg = ws_stream.next().await.unwrap().unwrap();
            let raw_res_body = msg.to_text().unwrap();
            let psbt = ctx.process_response(&mut raw_res_body.as_bytes()).expect("Failed to process response");
            let psbt = sender
                .wallet_process_psbt(&base64::encode(&psbt.serialize()), None, None, None)
                .expect("Failed to process PSBT")
                .psbt;
            let tx = sender
                .finalize_psbt(&psbt, Some(true))
                .expect("Failed to finalize PSBT")
                .hex
                .expect("Incomplete PSBT");
            let txid = sender
                .send_raw_transaction(&tx)
                .expect("Failed to send raw transaction");
            println!("Sent transaction: {}", txid);
        });

        tokio::try_join!(receive_thread, sender_thread).unwrap();
    }

    fn handle_payjoin_req(receiver: Client, body: impl std::io::Read, query: &str, headers: impl payjoin::receive::Headers) -> Result<String, Error> {
        println!("handle_payjoin_post");
        let proposal = payjoin::receive::UncheckedProposal::from_request(body, query, headers)?;
        
        // in a payment processor where the sender could go offline, this is where you schedule to broadcast the original_tx
        let _to_broadcast_in_failure_case = proposal.get_transaction_to_schedule_broadcast();

        // The network is used for checks later
        let network = bitcoin::Network::Regtest;

        // Receive Check 1: Can Broadcast
        let proposal = proposal.check_can_broadcast(|tx| {
            let raw_tx = bitcoin::consensus::encode::serialize_hex(&tx);
            let mempool_results = 
                receiver
                    .test_mempool_accept(&[raw_tx])
                    .expect("bitcoind error");
            match mempool_results.first() {
                Some(result) => Ok(result.allowed),
                None => panic!("bitcoind error: no mempool results"),
            }
        })?;
        println!("check1");

        // Receive Check 2: receiver can't sign for proposal inputs
        let proposal = proposal.check_inputs_not_owned(|input| {
            if let Ok(address) = bitcoin::Address::from_script(input, network) {
                receiver
                    .get_address_info(&address)
                    .map(|info| info.is_mine.unwrap_or(false))
                    .map_err(|e| Error::Server(e.into()))
            } else {
                Ok(false)
            }
        })?;
        println!("check2");
        // Receive Check 3: receiver can't sign for proposal inputs
        let proposal = proposal.check_no_mixed_input_scripts()?;
        println!("check3");

        // Receive Check 4: have we seen this input before? More of a check for non-interactive i.e. payment processor receivers.
        let payjoin = proposal.check_no_inputs_seen_before(|_| {
            Ok(false) // assume inputs not seen. this is a test.
        })?;
        println!("check4");

        let mut payjoin = payjoin.identify_receiver_outputs(|output_script| {
            if let Ok(address) = bitcoin::Address::from_script(output_script, network) {
                receiver
                    .get_address_info(&address)
                    .map(|info| info.is_mine.unwrap_or(false))
                    .map_err(|e| Error::Server(e.into()))
            } else {
                Ok(false)
            }
        })?;

        // Select receiver payjoin inputs.
        _ = try_contributing_inputs(&mut payjoin, &receiver).expect("Failed to contribute inputs");

        let receiver_substitute_address = receiver
            .get_new_address(None, None)
            .map_err(|e| Error::Server(e.into()))?
            .assume_checked();
        payjoin.substitute_output_address(receiver_substitute_address);

        let payjoin_proposal_psbt = payjoin.apply_fee(Some(1))?;

        println!("Extracted PSBT: {:#?}", payjoin_proposal_psbt);
        // Sign payjoin psbt
        let payjoin_base64_string = base64::encode(&payjoin_proposal_psbt.serialize());
        // `wallet_process_psbt` adds available utxo data and finalizes
        let payjoin_proposal_psbt = receiver
            .wallet_process_psbt(&payjoin_base64_string, None, None, Some(false))
            .map_err(|e| Error::Server(e.into()))?
            .psbt;
        let payjoin_proposal_psbt = Psbt::from_str(&payjoin_proposal_psbt).unwrap();
        let payjoin_proposal_psbt = payjoin.prepare_psbt(payjoin_proposal_psbt)?;
        println!("Receiver's Payjoin proposal PSBT Rsponse: {:#?}", payjoin_proposal_psbt);

        let payload = base64::encode(&payjoin_proposal_psbt.serialize());
        println!("successful response");
        Ok(payload)
    }

    fn try_contributing_inputs(
        payjoin: &mut payjoin::receive::PayjoinProposal,
        receiver: &Client,
    ) -> Result<(), ()> {
        let available_inputs = receiver
            .list_unspent(None, None, None, None, None)
            .expect("Failed to list unspent from bitcoind");
        let candidate_inputs: HashMap<Amount, OutPoint> = available_inputs
            .iter()
            .map(|i| (i.amount, OutPoint { txid: i.txid, vout: i.vout }))
            .collect();

        let selected_outpoint = payjoin.try_preserving_privacy(candidate_inputs).expect("gg");
        let selected_utxo = available_inputs
            .iter()
            .find(|i| i.txid == selected_outpoint.txid && i.vout == selected_outpoint.vout)
            .expect("This shouldn't happen. Failed to retrieve the privacy preserving utxo from those we provided to the seclector.");
        println!("selected utxo: {:#?}", selected_utxo);

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
}