use std::net::TcpListener;
use tungstenite::accept;
use hyper::Body;
use hyper::service::{make_service_fn, service_fn};
use hyper::StatusCode;
use tokio::sync::{mpsc, oneshot};
use tungstenite::Message;

use payjoin::relay;

#[tokio::main]
async fn main() {
    let server = TcpListener::bind("127.0.0.1:3012").unwrap();
    println!("REElay listening on ws://127.0.0.1:3012 😡");
    let (tx, mut rx) = mpsc::channel::<(relay::Request, oneshot::Sender<relay::Response>)>(1);

    tokio::spawn(async move {
        for stream in server.incoming() {
            println!("New ws connection!");
            let mut websocket = accept(stream.unwrap()).unwrap();
            let msg = websocket.read_message().unwrap();
            println!("Received: {}, awaiting Original PSBT", msg);
            let (relay_req, res_tx) = rx.recv().await.unwrap();
            // relay Original PSBT request to receiver via websocket
            let serialized_req = serde_json::to_string(&relay_req).unwrap();
            let post = Message::Text(serialized_req.to_string());
            println!("Received Original PSBT, relaying to receiver via websocket");
            websocket.write_message(post).unwrap();
            println!("Awaiting Payjoin PSBT from receiver via websocket"); // does this need to be async? break because block?
            // TODO await ws client transform Original PSBT into Payjoin PSBT
            let msg = websocket.read_message().unwrap();
            let serialized_res =  msg.into_text().unwrap();
            let res = serde_json::from_str::<relay::Response>(&serialized_res).unwrap();
            println!("Received Payjoin PSBT res {:#?}, relaying to sender via http", serialized_res);
            // delay 200ms
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            let sent = res_tx.send(res);
            println!("sent to http server via res_tx: {:?}", sent);
            break;
        }
    });
   
    // run HTTP server. On Post PJ, relay to websocket
    let make_svc = make_service_fn(move |_| {
        let tx = tx.clone();
        async move {
            let handler = move |req| handle_http_req(tx.clone(), req);
            Ok::<_, hyper::Error>(service_fn(handler))
        }
    });

    let server = hyper::Server::bind(&([127, 0, 0, 1], 3000).into()).serve(make_svc);
    println!("REElay configured to listen on http://127.0.0.1:3000 😡");
    server.await.unwrap();
}

async fn handle_http_req(
    tx: mpsc::Sender<(relay::Request, oneshot::Sender<relay::Response<'_>>)>,
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
            let (res_tx, res_rx) = oneshot::channel();
            tx.send((relay_req, res_tx)).await.unwrap();
            println!("Relayed req to ws channel from HTTP, awaiting Response");
            let res = res_rx.await.unwrap(); // TODO THIS NEVER GETS CALLED???
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
