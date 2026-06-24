use axum::extract::Request;
use axum::http::Method;
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

/// Records one completed HTTP request with bounded `endpoint` and `method`
/// labels.
///
/// The labels are normalized to a small fixed set by `endpoint_label` and
/// `method_label` before they reach the metric, so a client cannot inflate
/// label cardinality. Completion is recorded after `next.run` resolves, which
/// is when the response head is produced: a request cancelled before then
/// never reaches `http_requests_total`, but one cancelled while its body is
/// still streaming is counted as completed.
pub async fn track_metrics(
    metrics: axum::extract::State<MetricsService>,
    req: Request,
    next: Next,
) -> Response {
    let method = method_label(req.method());
    let endpoint = endpoint_label(req.uri().path());

    let response = next.run(req).await;
    let status = response.status().as_u16();

    metrics.record_http_request(endpoint, method, status);

    response
}

/// Collapses a request path to a bounded set of `endpoint` label values.
///
/// The path is client-controlled and otherwise unbounded (opt-in gateway
/// URLs, 404 scanner probes), so it must never reach a metric label verbatim:
/// OpenTelemetry aggregates label sets in memory under cumulative temporality
/// and never evicts them, so unbounded labels are a memory-exhaustion vector.
///
/// Every request maps to exactly one of:
/// - `/{mailbox}` -- a 13-character bech32 mailbox id (also keeps the id out
///   of metrics)
/// - `/{gateway}` -- an opt-in gateway path (`/http://...` or `/https://...`),
///   the RFC 9540 and WebSocket bootstrap forms recognized by the relay
/// - `/`, `/health`, `/ohttp-keys`, `/.well-known/ohttp-gateway` -- exact,
///   server-defined routes. These are a fixed, finite set, so echoing the path
///   verbatim cannot inflate label cardinality, and keeping them distinct lets
///   health checks, key fetches, and gateway traffic be told apart in metrics.
/// - `other` -- everything else: 404s, scanner probes, and the `CONNECT`
///   bootstrap whose path is a client-controlled authority (its `method` label
///   already distinguishes it)
pub(crate) fn endpoint_label(path: &str) -> &'static str {
    const BECH32_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    // Exact, server-defined routes shared by the relay and directory. The set
    // is fixed and finite, so returning the path verbatim is cardinality-safe.
    match path {
        "/" => return "/",
        "/health" => return "/health",
        "/ohttp-keys" => return "/ohttp-keys",
        "/.well-known/ohttp-gateway" => return "/.well-known/ohttp-gateway",
        _ => {}
    }
    if let Some(segment) = path.strip_prefix('/') {
        if segment.len() == 13
            && segment.bytes().all(|b| BECH32_CHARSET.contains(&b.to_ascii_lowercase()))
        {
            return "/{mailbox}";
        }
    }
    if path.starts_with("/http://") || path.starts_with("/https://") {
        return "/{gateway}";
    }
    "other"
}

/// Clamps an HTTP method to a bounded set of `method` label values.
///
/// `http::Method` admits arbitrary extension tokens, which are client
/// controlled, so any method outside the standard set collapses to `other` to
/// keep label cardinality bounded.
pub(crate) fn method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::DELETE => "DELETE",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        Method::CONNECT => "CONNECT",
        Method::PATCH => "PATCH",
        Method::TRACE => "TRACE",
        _ => "other",
    }
}

/// Tracks per-request lifecycle metrics: marks the request started and in
/// flight on arrival and marks it no longer in flight when it finishes.
///
/// The in-flight count is decremented by the `InFlightGuard` held across the
/// inner future, so it is corrected even if the request is cancelled (a
/// long-poll client disconnects) or the handler panics -- cases where a manual
/// decrement after `next.run` would be skipped and leak the count upward.
pub async fn track_connections(
    metrics: axum::extract::State<MetricsService>,
    req: Request,
    next: Next,
) -> Response {
    let _guard = metrics.track_request();
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENDPOINT_LABELS: &[&str] = &[
        "/{mailbox}",
        "/{gateway}",
        "/",
        "/health",
        "/ohttp-keys",
        "/.well-known/ohttp-gateway",
        "other",
    ];

    #[test]
    fn endpoint_label_maps_known_templates() {
        assert_eq!(endpoint_label("/"), "/");
        assert_eq!(endpoint_label("/health"), "/health");
        assert_eq!(endpoint_label("/ohttp-keys"), "/ohttp-keys");
        assert_eq!(endpoint_label("/.well-known/ohttp-gateway"), "/.well-known/ohttp-gateway");
        // A 13-character bech32 mailbox id, lower and upper case.
        let mailbox = format!("/{}", "q".repeat(13));
        assert_eq!(endpoint_label(&mailbox), "/{mailbox}");
        let mailbox_upper = format!("/{}", "Q".repeat(13));
        assert_eq!(endpoint_label(&mailbox_upper), "/{mailbox}");
        // Opt-in gateway paths (RFC 9540 and WebSocket bootstrap forms).
        assert_eq!(endpoint_label("/https://gateway.example/ohttp"), "/{gateway}");
        assert_eq!(endpoint_label("/http://gateway.example"), "/{gateway}");
    }

    #[test]
    fn endpoint_label_collapses_everything_else_to_other() {
        let twelve = format!("/{}", "q".repeat(12));
        let fourteen = format!("/{}", "q".repeat(14));
        // 'b' is not in the bech32 charset, so 13 of them is not a mailbox.
        let not_bech32 = format!("/{}", "b".repeat(13));
        for path in [
            "",              // authority-form / empty path (e.g. CONNECT)
            "/wp-login.php", // scanner probe
            not_bech32.as_str(),
            twelve.as_str(),   // wrong length
            fourteen.as_str(), // wrong length
            "/http",           // gateway prefix not satisfied
            "/https:/gateway", // malformed gateway prefix
            "/../../etc/passwd",
            "/healthz",
            "/ohttp-keys/extra",
            "/.well-known",
            "/.well-known/ohttp-gateway/extra",
        ] {
            assert_eq!(endpoint_label(path), "other", "path {path:?} must collapse to other");
        }
    }

    #[test]
    fn endpoint_label_never_escapes_the_bounded_set() {
        for path in ["/", &format!("/{}", "q".repeat(13)), "/https://x", "/anything", "", "/a/b/c"]
        {
            assert!(
                ENDPOINT_LABELS.contains(&endpoint_label(path)),
                "endpoint label for {path:?} escaped the bounded set"
            );
        }
    }

    #[test]
    fn method_label_collapses_extension_methods_to_other() {
        let custom = Method::from_bytes(b"FROBNICATE").expect("valid method token");
        assert_eq!(method_label(&custom), "other");
    }
}
