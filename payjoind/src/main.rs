use std::collections::HashMap;
use bitcoincore_rpc::bitcoin::Txid;
use payjoin::bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use bitcoincore_rpc::RpcApi;
use payjoin::{UriExt, PjUriExt};
use std::convert::TryFrom;

use jsonrpc_http_server::{ServerBuilder};
use jsonrpc_derive::rpc;


fn main() {
    let mut args = std::env::args_os();
    let _program_name = args
        .next()
        .expect("not even program name given");
    let port = args
        .next()
        .expect("Missing arguments: port cookie_file")
        .into_string()
        .expect("port is not UTF-8")
        .parse::<u16>()
        .expect("port must be a number");

    let cookie_file = args
        .next()
        .expect("Missing arguments: cookie_file");

    let server = Payjoind::new(port, cookie_file.into());
    server.wait()
}

fn load_psbt_from_base64(mut input: impl std::io::Read) -> Result<Psbt, payjoin::bitcoin::consensus::encode::Error> {
    use payjoin::bitcoin::consensus::Decodable;    
 
    let reader = base64::read::DecoderReader::new(&mut input, base64::Config::new(base64::CharacterSet::Standard, true));
    Psbt::consensus_decode(reader)    
}

fn serialize_psbt(psbt: &Psbt) -> String {
    use payjoin::bitcoin::consensus::Encodable;
                                    
    let mut encoder = base64::write::EncoderWriter::new(Vec::new(), base64::STANDARD);
    psbt.consensus_encode(&mut encoder)
        .expect("Vec doesn't return errors in its write implementation");
    String::from_utf8(encoder.finish()
        .expect("Vec doesn't return errors in its write implementation")).unwrap()
}

struct Payjoind {
    server: jsonrpc_http_server::Server,
}

impl Payjoind {
    pub fn new(port: u16, cookie_file: std::path::PathBuf) -> Self {
        let bitcoind = bitcoincore_rpc::Client::new(&format!("http://127.0.0.1:{}", port), bitcoincore_rpc::Auth::CookieFile(cookie_file)).unwrap();
        let mut io = jsonrpc_core::IoHandler::new();
        let rpc = RpcImpl { bitcoind };
        io.extend_with(rpc.to_delegate());

        let server = ServerBuilder::new(io)
            .threads(3)
            .start_http(&"127.0.0.1:3030".parse().unwrap())
            .unwrap();

        Self { server }
    }

    pub fn wait(self) {
        self.server.wait()
    }
}

#[rpc(server)]
pub trait Rpc {
    #[rpc(name = "sendpayjoin")]
    fn send_payjoin(&self, bip21: String) -> jsonrpc_core::Result<Txid>;
}

struct RpcImpl {
    bitcoind: bitcoincore_rpc::Client,
}

impl Rpc for RpcImpl {
    fn send_payjoin(&self, bip21: String) -> jsonrpc_core::Result<Txid> {
        let link = payjoin::Uri::try_from(&*bip21).unwrap();

        let link = link.check_pj_supported().unwrap_or_else(|_| panic!("The provided URI doesn't support payjoin (BIP78)"));

        if link.amount.is_none() {
            panic!("please specify the amount in the Uri");
        }

        let mut outputs = HashMap::with_capacity(1);
        outputs.insert(link.address.to_string(), link.amount.unwrap());

        let options = bitcoincore_rpc::json::WalletCreateFundedPsbtOptions {
            lock_unspent: Some(true),
            fee_rate: Some(payjoin::bitcoin::Amount::from_sat(2000)),
            ..Default::default()
        };
        let psbt = self.bitcoind.wallet_create_funded_psbt(
            &[], // inputs
            &outputs,
            None, // locktime
            Some(options),
            None,
        ).expect("failed to create PSBT").psbt;
        let psbt = self.bitcoind
            .wallet_process_psbt(&psbt, None, None, None)
            .unwrap()
            .psbt;
        let psbt = load_psbt_from_base64(psbt.as_bytes()).unwrap();
        println!("Original psbt: {:#?}", psbt);
        let pj_params = payjoin::sender::Params::with_fee_contribution(payjoin::bitcoin::Amount::from_sat(10000), None);
        let (req, ctx) = link.create_pj_request(psbt, pj_params).unwrap();
        let response = reqwest::blocking::Client::new()
            .post(req.url)
            .body(req.body)
            .header("Content-Type", "text/plain")
            .send()
            .expect("failed to communicate");
            //.error_for_status()
            //.unwrap();
        let psbt = ctx.process_response(response).unwrap();
        println!("Proposed psbt: {:#?}", psbt);
        let psbt = self.bitcoind
            .wallet_process_psbt(&serialize_psbt(&psbt), None, None, None)
            .unwrap()
            .psbt;
        let tx = self.bitcoind
            .finalize_psbt(&psbt, Some(true))
            .unwrap()
            .hex
            .expect("incomplete psbt");
        self.bitcoind.send_raw_transaction(&tx).map_err(|e| {
            println!("Error: {}", e);
            jsonrpc_core::Error::internal_error()
        })
    }
}