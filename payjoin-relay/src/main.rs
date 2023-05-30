use std::net::TcpListener;
use std::thread::spawn;
use tungstenite::accept;

fn main() {
    let mut buf: String = "".to_string();

    let server = TcpListener::bind("127.0.0.1:3012").unwrap();
    println!("REElay listening on 127.0.0.1:3012 😡");
    for stream in server.incoming() {
        spawn (move || {
            let mut websocket = accept(stream.unwrap()).unwrap();
            loop {
                let msg = websocket.read_message().unwrap();

                // We do not want to send back ping/pong messages.
                println!("Received: {}", msg);
                if msg.is_binary() || msg.is_text() {
                    websocket.write_message(msg).unwrap();
                }
            }
        });
    }
}
