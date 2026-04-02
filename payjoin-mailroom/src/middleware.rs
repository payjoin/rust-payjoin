use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

use crate::metrics::MetricsService;

#[cfg(feature = "access-control")]
#[derive(Clone, Debug)]
pub struct MaybePeerIp(pub Option<std::net::IpAddr>);

#[cfg(feature = "access-control")]
pub async fn check_geoip(req: Request, next: Next) -> Response {
    use axum::http::StatusCode;

    let geoip = req.extensions().get::<Option<std::sync::Arc<crate::access_control::IpFilter>>>();

    if let Some(Some(geoip)) = geoip {
        if let Some(connect_info) =
            req.extensions().get::<axum::extract::ConnectInfo<MaybePeerIp>>()
        {
            if let Some(ip) = connect_info.0 .0 {
                if !geoip.check_ip(ip) {
                    tracing::warn!("Blocked request from {ip} due to GeoIP policy");
                    return Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(axum::body::Body::empty())
                        .expect("valid response");
                }
            }
        }
    }

    next.run(req).await
}

pub async fn track_metrics(
    metrics: axum::extract::State<MetricsService>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().to_string();
    let path = sanitize_short_id(req.uri().path());

    let response = next.run(req).await;
    let status = response.status().as_u16();

    metrics.record_http_request(&path, &method, status);

    response
}

fn sanitize_short_id(path: &str) -> String {
    // This function ensures that ShortID isn't recorded in the metrics
    const BECH32_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    match path.strip_prefix('/') {
        Some(segment)
            if segment.len() == 13
                && segment.bytes().all(|b| BECH32_CHARSET.contains(&b.to_ascii_lowercase())) =>
            "/{mailbox}".to_string(),
        _ => path.to_string(),
    }
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
