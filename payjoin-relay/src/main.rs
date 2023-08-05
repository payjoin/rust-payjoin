use std::net::TcpListener;
use std::sync::Arc;
use tungstenite::accept;
use hyper::Body;
use hyper::service::{make_service_fn, service_fn};
use hyper::StatusCode;
use tokio::sync::{mpsc, oneshot, Mutex};
use tungstenite::Message;

use payjoin::relay;

#[tokio::main]
async fn main() {
    let server = TcpListener::bind("127.0.0.1:3012").unwrap();
    println!("REElay listening on ws://127.0.0.1:3012 😡");
    let req_buffer = Buffer::new();
    let res_buffer = Buffer::new();
    
    let ws_req_buffer = req_buffer.clone();
    let ws_res_buffer = res_buffer.clone();
    tokio::spawn(async move {
        // run websocket server. On connection, await Original PSBT, relay to http server
        for stream in server.incoming() {
            println!("New ws connection!");
            let mut websocket = accept(stream.unwrap()).unwrap();
            let msg = websocket.read_message().unwrap();
            println!("Received: {}, awaiting Original PSBT", msg);

            if msg.to_text().unwrap() == "receiver" {
                let buffered_req = ws_req_buffer.clone().pop().await;
                // relay Original PSBT request to receiver via websocket
                let post = Message::Text(buffered_req.to_string());
                println!("Received Original PSBT, relaying to receiver via websocket");
                websocket.write_message(post).unwrap();
    
                println!("Awaiting Payjoin PSBT from receiver via websocket"); // does this need to be async? break because block?
                // TODO await ws client transform Original PSBT into Payjoin PSBT
                let msg = websocket.read_message().unwrap();
                let serialized_res =  msg.into_text().unwrap();
                println!("Received Payjoin PSBT res {:#?}, relaying to sender via http", serialized_res);
    
                ws_res_buffer.push(serialized_res).await;
                println!("sent to http server via push");
                break;
            }
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

            let serialized_res = res_buffer.pop().await;
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

    async fn pop(&self) -> String {
        let mut buffer = self.buffer.lock().await;
        let mut contents = buffer.clone();
        if contents.is_empty() {
            drop(buffer);
            // wait for a signal that a new request has been added
            self.receiver.lock().await.recv().await;
            buffer = self.buffer.lock().await;
            contents = buffer.clone();
        }
        *buffer = String::new();
        contents
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_buffer() {
        let buffer = Buffer::new();
        let buffer_clone = buffer.clone();
        tokio::spawn(async move {
            buffer_clone.push("test".to_string()).await;
        });
        buffer.pop().await;
    }
}