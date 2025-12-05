use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{Sink, SinkExt, StreamExt};
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response};
use hyper_tungstenite::HyperWebsocket;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{tungstenite, WebSocketStream};
use tracing::{error, instrument};

use crate::error::Error;
use crate::gateway_uri::GatewayUri;

pub(crate) fn is_websocket_request(req: &Request<Incoming>) -> bool {
    hyper_tungstenite::is_upgrade_request(req)
}

#[instrument]
pub(crate) async fn try_upgrade(
    req: &mut Request<Incoming>,
    gateway_origin: GatewayUri,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Error> {
    let gateway_addr = gateway_origin
        .to_socket_addr()
        .await
        .map_err(|e| Error::InternalServerError(Box::new(e)))?
        .ok_or_else(|| Error::NotFound)?;

    let (res, websocket) = hyper_tungstenite::upgrade(req, None)
        .map_err(|e| Error::BadRequest(format!("Error upgrading to websocket: {}", e)))?;

    tokio::spawn(async move {
        if let Err(e) = serve_websocket(websocket, gateway_addr).await {
            error!("Error in websocket connection: {e}");
        }
    });
    let (parts, body) = res.into_parts();
    let boxbody = body.map_err(|never| match never {}).boxed();
    Ok(Response::from_parts(parts, boxbody))
}

/// Stream WebSocket frames from the client to the gateway server's TCP socket and vice versa.
#[instrument]
async fn serve_websocket(
    websocket: HyperWebsocket,
    gateway_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
    let mut tcp_stream = tokio::net::TcpStream::connect(gateway_addr).await?;
    let mut ws_io = WsIo::new(websocket.await?);
    let (_, _) = tokio::io::copy_bidirectional(&mut ws_io, &mut tcp_stream).await?;
    Ok(())
}

pub struct WsIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ws_stream: WebSocketStream<S>,
    read_buffer: Vec<u8>,
}

impl<S> WsIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(ws_stream: WebSocketStream<S>) -> Self {
        WsIo { ws_stream, read_buffer: Vec::new() }
    }
}

impl<S> AsyncRead for WsIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let self_mut = self.get_mut();

        // If the read buffer has data, use it first.
        if !self_mut.read_buffer.is_empty() {
            let len = std::cmp::min(buf.remaining(), self_mut.read_buffer.len());
            buf.put_slice(&self_mut.read_buffer[..len]);
            self_mut.read_buffer.drain(..len);
            return Poll::Ready(Ok(()));
        }
        // Otherwise, try to read a new frame.
        match self_mut.ws_stream.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(message))) => match message {
                Message::Binary(data) => {
                    self_mut.read_buffer.extend_from_slice(&data);
                    let len = std::cmp::min(buf.remaining(), self_mut.read_buffer.len());
                    buf.put_slice(&self_mut.read_buffer[..len]);
                    self_mut.read_buffer.drain(..len);
                    Poll::Ready(Ok(()))
                }
                Message::Ping(data) => start_send(&mut self_mut.ws_stream, Message::Pong(data)),
                Message::Pong(_) => {
                    // Usually, no action is needed on pong messages
                    Poll::Pending
                }
                Message::Close(_) => start_send(&mut self_mut.ws_stream, Message::Close(None)),
                _ => Poll::Pending,
            },
            Poll::Ready(None) => {
                // No more messages will be received because the WebSocket stream is closed.
                // If there's no data left in the read buffer, we signify EOF by returning Ok.
                if self_mut.read_buffer.is_empty() {
                    Poll::Ready(Ok(())) // Signify EOF
                } else {
                    // If there's still data left in the buffer, we need to return that first.
                    // This ensures that the caller can consume all remaining data before receiving EOF.
                    let len = std::cmp::min(buf.remaining(), self_mut.read_buffer.len());
                    buf.put_slice(&self_mut.read_buffer[..len]);
                    self_mut.read_buffer.drain(..len);
                    Poll::Ready(Ok(()))
                }
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(map_ws_error(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> AsyncWrite for WsIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let self_mut = self.get_mut();
        match Pin::new(&mut self_mut.ws_stream).poll_ready(cx) {
            Poll::Ready(Ok(())) =>
                start_send(&mut self_mut.ws_stream, Message::Binary(data.to_vec().into()))
                    .map(|r| r.map(|_| data.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(map_ws_error(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().ws_stream).poll_flush(cx).map_err(map_ws_error)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().ws_stream).poll_close(cx).map_err(map_ws_error)
    }
}

fn start_send(
    ws_stream: &mut WebSocketStream<impl AsyncRead + AsyncWrite + Unpin>,
    data: Message,
) -> Poll<Result<(), io::Error>> {
    Poll::Ready(ws_stream.start_send_unpin(data).map_err(map_ws_error))
}

fn map_ws_error(e: tungstenite::Error) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, format!("Tungstenite error: {}", e))
}
