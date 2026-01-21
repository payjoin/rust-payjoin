use std::fmt::Debug;
use std::net::SocketAddr;

use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tracing::{error, instrument};

use crate::error::Error;
use crate::{empty, GatewayUri};

pub(crate) fn is_connect_request<B>(req: &Request<B>) -> bool { Method::CONNECT == req.method() }

#[instrument]
pub(crate) async fn try_upgrade<B>(
    req: Request<B>,
    gateway_origin: GatewayUri,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Error>
where
    B: Send + Debug + 'static,
{
    let addr = gateway_origin
        .to_socket_addr()
        .await
        .map_err(|e| Error::InternalServerError(Box::new(e)))?
        .ok_or_else(|| Error::NotFound)?;

    tokio::task::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Err(e) = tunnel(upgraded, addr).await {
                    error!("server io error: {}", e);
                };
            }
            Err(e) => error!("upgrade error: {}", e),
        }
    });

    Ok(Response::new(empty()))
}

/// Create a TCP connection to host:port, build a tunnel between the connection and
/// the upgraded connection
#[instrument]
async fn tunnel(upgraded: Upgraded, addr: SocketAddr) -> std::io::Result<()> {
    let mut server = TcpStream::connect(addr).await?;
    let mut upgraded = TokioIo::new(upgraded);
    let (_, _) = tokio::io::copy_bidirectional(&mut upgraded, &mut server).await?;
    Ok(())
}
