use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::{Request, Response};
use tokio::sync::Semaphore;
use tracing::instrument;

use crate::metrics::MetricsService;
use crate::ohttp_relay::error::Error;
use crate::ohttp_relay::GatewayUri;

#[cfg(feature = "connect-bootstrap")]
pub mod connect;

#[cfg(feature = "ws-bootstrap")]
pub mod ws;

/// Maximum number of concurrent OHTTP bootstrap tunnels. Each tunnel pins two
/// file descriptors (the inbound upgraded socket and the outbound TCP stream),
/// so an unbounded number of them can exhaust the process descriptor limit.
pub(crate) const MAX_CONCURRENT_TUNNELS: usize = 1024;

/// Maximum lifetime of a single bootstrap tunnel. OHTTP key bootstrap is a
/// short request/response exchange, so a tunnel still open after this is
/// assumed stalled and is torn down to release its descriptors.
pub(crate) const TUNNEL_TIMEOUT: Duration = Duration::from_secs(60);

/// Resource bounds shared by the CONNECT and WebSocket bootstrap tunnels.
///
/// Bootstrap tunnels are the only relay path that holds descriptors open for an
/// unbounded time without these limits: a stalled or malicious client can pin
/// two descriptors per tunnel indefinitely. The semaphore caps concurrency and
/// the timeout caps lifetime, so total descriptor use stays bounded.
#[derive(Debug, Clone)]
pub(crate) struct TunnelLimits {
    /// Caps the number of concurrent tunnels.
    pub(crate) semaphore: Arc<Semaphore>,
    /// Caps the lifetime of each tunnel.
    pub(crate) timeout: Duration,
}

impl Default for TunnelLimits {
    fn default() -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_TUNNELS)),
            timeout: TUNNEL_TIMEOUT,
        }
    }
}

/// Records a bootstrap tunnel as open for as long as it is held, and records it
/// closed on drop. Holding the guard inside the tunnel task means the close is
/// recorded however the tunnel ends -- normal close, I/O error, timeout
/// teardown, or panic -- so the active-tunnel gauge cannot drift.
pub(crate) struct TunnelGuard {
    metrics: MetricsService,
}

impl TunnelGuard {
    pub(crate) fn open(metrics: MetricsService) -> Self {
        metrics.record_tunnel_open();
        Self { metrics }
    }
}

impl Drop for TunnelGuard {
    fn drop(&mut self) { self.metrics.record_tunnel_close(); }
}

/// Drive a bootstrap tunnel to completion, tearing it down if it stays open
/// longer than `timeout`. The deadline covers the whole tunnel lifecycle (DNS,
/// HTTP upgrade, outbound connect, and byte proxying), so a stalled client
/// cannot pin its descriptors past the deadline. Returns `Some(output)` when
/// the tunnel finished on its own and `None` when the deadline tore it down.
pub(crate) async fn run_tunnel_within<F: std::future::Future>(
    timeout: Duration,
    tunnel: F,
) -> Option<F::Output> {
    tokio::time::timeout(timeout, tunnel).await.ok()
}

#[instrument(skip(limits, metrics))]
pub(crate) async fn handle_ohttp_keys<B>(
    req: Request<B>,
    gateway_origin: GatewayUri,
    limits: &TunnelLimits,
    metrics: &MetricsService,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Error>
where
    B: Send + Debug + 'static,
{
    #[cfg(feature = "connect-bootstrap")]
    if connect::is_connect_request(&req) {
        return connect::try_upgrade(req, gateway_origin, limits, metrics).await;
    }

    #[cfg(feature = "ws-bootstrap")]
    if ws::is_websocket_request(&req) {
        return ws::try_upgrade(req, gateway_origin, limits, metrics).await;
    }

    Err(Error::BadRequest("Not a supported proxy upgrade request".to_string()))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::run_tunnel_within;

    #[tokio::test(start_paused = true)]
    async fn stalled_tunnel_is_torn_down_at_deadline() {
        // A tunnel future that never makes progress must be torn down once the
        // timeout elapses, so its descriptors are released rather than pinned.
        let never = std::future::pending::<std::io::Result<()>>();
        let outcome = run_tunnel_within(Duration::from_secs(30), never).await;
        assert!(outcome.is_none(), "stalled tunnel must time out");
    }

    #[tokio::test(start_paused = true)]
    async fn completed_tunnel_returns_its_result() {
        // A tunnel that finishes before the deadline returns its own result
        // untouched.
        let done = std::future::ready(Ok::<(), std::io::Error>(()));
        let outcome = run_tunnel_within(Duration::from_secs(30), done).await;
        assert!(matches!(outcome, Some(Ok(()))), "completed tunnel returns its result");
    }
}
