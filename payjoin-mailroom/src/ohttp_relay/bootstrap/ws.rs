use std::fmt::Debug;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{Sink, SinkExt, StreamExt};
use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::header::{CONNECTION, SEC_WEBSOCKET_ACCEPT, SEC_WEBSOCKET_KEY, UPGRADE};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::OwnedSemaphorePermit;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{tungstenite, WebSocketStream};
use tracing::{debug, error, instrument};

use crate::metrics::MetricsService;
use crate::ohttp_relay::bootstrap::{run_tunnel_within, TunnelGuard, TunnelLimits};
use crate::ohttp_relay::empty;
use crate::ohttp_relay::error::Error;
use crate::ohttp_relay::gateway_uri::GatewayUri;

/// Check if the request is a WebSocket upgrade request.
///
/// This is done manually to support generic body types.
/// When bootstrapping moves to axum, this can be replaced with
/// `axum::extract::ws::WebSocketUpgrade`.
pub(crate) fn is_websocket_request<B>(req: &Request<B>) -> bool {
    let dominated_by_upgrade = req
        .headers()
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("upgrade"))
        .unwrap_or(false);

    let upgrade_to_websocket = req
        .headers()
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    dominated_by_upgrade && upgrade_to_websocket && req.headers().contains_key(SEC_WEBSOCKET_KEY)
}

/// Upgrade the request to a WebSocket connection and proxy to the gateway.
///
/// This performs the WebSocket handshake to support generic body types.
/// When bootstrapping moves to axum, this can be replaced with
/// `axum::extract::ws::WebSocketUpgrade`.
#[instrument(skip(limits, metrics))]
pub(crate) async fn try_upgrade<B>(
    req: Request<B>,
    gateway_origin: GatewayUri,
    limits: &TunnelLimits,
    metrics: &MetricsService,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Error>
where
    B: Send + Debug + 'static,
{
    // Reject before doing any work when the tunnel budget is exhausted, so a
    // flood of bootstrap requests cannot pin an unbounded number of file
    // descriptors.
    let permit = match limits.semaphore.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            metrics.record_tunnel_shed();
            return Err(Error::Unavailable(limits.timeout));
        }
    };

    let key = req
        .headers()
        .get(SEC_WEBSOCKET_KEY)
        .ok_or_else(|| Error::BadRequest("Missing Sec-WebSocket-Key header".to_string()))?
        .to_str()
        .map_err(|_| Error::BadRequest("Invalid Sec-WebSocket-Key header".to_string()))?
        .to_string();

    let accept_key = derive_accept_key(key.as_bytes());

    let timeout = limits.timeout;
    let guard = TunnelGuard::open(metrics.clone());
    tokio::spawn(async move {
        let _guard = guard;
        match run_tunnel_within(timeout, serve_after_upgrade(req, gateway_origin, permit)).await {
            Some(Ok(())) => {}
            Some(Err(e)) => error!("Error in websocket connection: {e}"),
            None => debug!("websocket tunnel exceeded {timeout:?}, closing"),
        }
    });

    let res = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(UPGRADE, "websocket")
        .header(CONNECTION, "Upgrade")
        .header(SEC_WEBSOCKET_ACCEPT, accept_key)
        .body(empty())
        .map_err(|e| Error::InternalServerError(Box::new(e)))?;

    Ok(res)
}

async fn serve_after_upgrade<B>(
    req: Request<B>,
    gateway_origin: GatewayUri,
    permit: OwnedSemaphorePermit,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>
where
    B: Send + Debug + 'static,
{
    // Hold the permit for the entire tunnel lifecycle: DNS, HTTP upgrade,
    // outbound connect, and byte proxying.
    let _permit = permit;
    let gateway_addr = gateway_origin.to_socket_addr().await?.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "gateway resolved to no addresses")
    })?;
    let upgraded = hyper::upgrade::on(req).await?;
    let ws_stream = WebSocketStream::from_raw_socket(
        TokioIo::new(upgraded),
        tungstenite::protocol::Role::Server,
        None,
    )
    .await;
    serve_websocket(ws_stream, gateway_addr).await
}

/// Stream WebSocket frames from the client to the gateway server's TCP socket and vice versa.
#[instrument(skip(ws_stream))]
async fn serve_websocket<S>(
    ws_stream: WebSocketStream<S>,
    gateway_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut tcp_stream = tokio::net::TcpStream::connect(gateway_addr).await?;
    let mut ws_io = WsIo::new(ws_stream);
    tokio::io::copy_bidirectional(&mut ws_io, &mut tcp_stream).await?;
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
