#[cfg(feature = "access-control")]
use std::sync::Arc;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

#[cfg(feature = "access-control")]
use crate::access_control::AccessControl;
use crate::metrics::MetricsService;

#[cfg(feature = "access-control")]
#[derive(Clone, Copy, Debug)]
pub struct MaybePeerIp(pub Option<std::net::IpAddr>);

pub async fn track_metrics(
    metrics: axum::extract::State<MetricsService>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();

    let response = next.run(req).await;
    let status = response.status().as_u16();

    metrics.record_http_request(&path, &method, status);

    response
}

#[cfg(feature = "access-control")]
pub async fn check_access_control(
    axum::extract::Extension(access_control): axum::extract::Extension<Option<Arc<AccessControl>>>,
    req: Request,
    next: Next,
) -> Response {
    use axum::response::IntoResponse;

    if let Some(ac) = access_control.as_ref() {
        let peer_ip = req
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip())
            .or_else(|| {
                req.extensions().get::<axum::extract::ConnectInfo<MaybePeerIp>>().and_then(|ci| {
                    let maybe_peer_ip = ci.0;
                    maybe_peer_ip.0
                })
            });
        if let Some(ip) = peer_ip {
            if !ac.check_ip(ip) {
                tracing::warn!("Blocked request from {}", ip);
                return (axum::http::StatusCode::FORBIDDEN, "").into_response();
            }
        }
    }
    next.run(req).await
}

pub async fn track_connections(
    metrics: axum::extract::State<MetricsService>,
    req: Request,
    next: Next,
) -> Response {
    metrics.record_connection_open();
    let response = next.run(req).await;
    metrics.record_connection_close();
    response
}
