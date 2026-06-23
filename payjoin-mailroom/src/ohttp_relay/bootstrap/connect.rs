use std::fmt::Debug;
use std::net::SocketAddr;

use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::upgrade::Upgraded;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;
use tracing::{debug, error, instrument};

use crate::ohttp_relay::bootstrap::{run_tunnel_within, TunnelLimits};
use crate::ohttp_relay::error::Error;
use crate::ohttp_relay::{empty, GatewayUri};

pub(crate) fn is_connect_request<B>(req: &Request<B>) -> bool { Method::CONNECT == req.method() }

#[instrument(skip(limits))]
pub(crate) async fn try_upgrade<B>(
    req: Request<B>,
    gateway_origin: GatewayUri,
    limits: &TunnelLimits,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Error>
where
    B: Send + Debug + 'static,
{
    // Reject before doing any work (including DNS resolution) when the tunnel
    // budget is exhausted, so a flood of bootstrap requests cannot pin an
    // unbounded number of file descriptors.
    let permit = match limits.semaphore.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return Err(Error::Unavailable(limits.timeout)),
    };

    let timeout = limits.timeout;
    tokio::task::spawn(async move {
        match run_tunnel_within(timeout, tunnel_after_upgrade(req, gateway_origin, permit)).await {
            Some(Ok(())) => {}
            Some(Err(e)) => error!("server io error: {}", e),
            None => debug!("tunnel exceeded {timeout:?}, closing"),
        }
    });

    Ok(Response::new(empty()))
}

async fn tunnel_after_upgrade<B>(
    req: Request<B>,
    gateway_origin: GatewayUri,
    permit: OwnedSemaphorePermit,
) -> std::io::Result<()>
where
    B: Send + Debug + 'static,
{
    // Hold the permit for the entire tunnel lifecycle: DNS, HTTP upgrade,
    // outbound connect, and byte proxying.
    let _permit = permit;
    let addr = gateway_origin.to_socket_addr().await?.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "gateway resolved to no addresses")
    })?;
    let upgraded = hyper::upgrade::on(req).await.map_err(std::io::Error::other)?;
    tunnel(upgraded, addr).await
}

/// Create a TCP connection to host:port, build a tunnel between the connection and
/// the upgraded connection
#[instrument]
async fn tunnel(upgraded: Upgraded, addr: SocketAddr) -> std::io::Result<()> {
    let mut server = TcpStream::connect(addr).await?;
    let mut upgraded = TokioIo::new(upgraded);
    tokio::io::copy_bidirectional(&mut upgraded, &mut server).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Arc;
    use std::time::Duration;

    use hyper::{Method, Request};
    use tokio::sync::Semaphore;

    use super::try_upgrade;
    use crate::ohttp_relay::bootstrap::TunnelLimits;
    use crate::ohttp_relay::error::Error;
    use crate::ohttp_relay::GatewayUri;

    #[tokio::test]
    async fn rejects_when_tunnel_budget_exhausted() {
        // No permits available: the next bootstrap request must be rejected
        // before any upgrade or gateway connection is attempted.
        let limits = TunnelLimits {
            semaphore: Arc::new(Semaphore::new(0)),
            timeout: Duration::from_secs(60),
        };
        let req = Request::builder()
            .method(Method::CONNECT)
            .uri("example.com:443")
            .body(())
            .expect("valid request");
        let gateway = GatewayUri::from_str("https://example.com").expect("valid gateway");

        let err = try_upgrade(req, gateway, &limits).await.expect_err("should be rejected");

        assert!(matches!(err, Error::Unavailable(_)));
    }
}
