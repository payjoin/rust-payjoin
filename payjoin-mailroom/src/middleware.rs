use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

use crate::metrics::MetricsService;

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
