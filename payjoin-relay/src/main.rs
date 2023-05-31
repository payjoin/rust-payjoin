use std::fmt;
use std::net::TcpListener;
use tungstenite::accept;
use tungstenite::Message;
use hyper::{Body, Request, Response, Server};
use hyper::service::{make_service_fn, service_fn};
use hyper::StatusCode;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    let server = TcpListener::bind("127.0.0.1:3012").unwrap();
    println!("REElay listening on ws://127.0.0.1:3012 😡");
    let (tx, mut rx) = mpsc::channel(1);

    tokio::spawn(async move {
        for stream in server.incoming() {
            println!("New ws connection!");
            let mut websocket = accept(stream.unwrap()).unwrap();
            let msg = websocket.read_message().unwrap();
            println!("Received: {}", msg);
            let res = rx.recv().await.unwrap();
            websocket.write_message(res).unwrap();
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

    let server = Server::bind(&([127, 0, 0, 1], 8080).into()).serve(make_svc);
    println!("REElay configured to listen on http://127.0.0.1:8080 😡");
    server.await.unwrap();
}

async fn handle_http_req(
    tx: mpsc::Sender<Message>,
    req: Request<Body>,
) -> Result<Response<Body>, hyper::Error> {
    match (req.method().clone(), req.uri().path()) {
        (hyper::Method::POST, "/") => {
            println!("POST /    received");
            let entire_body = hyper::body::to_bytes(req.into_body()).await.unwrap();
            tx.send(Message::Text(String::from_utf8(entire_body.to_vec()).unwrap())).await.unwrap();
            Ok::<Response<Body>, hyper::Error>(Response::new(Body::from("Posted")))
        },
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

struct ServerError {}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Server error")
    }
}