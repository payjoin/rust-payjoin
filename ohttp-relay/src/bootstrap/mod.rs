use http_body_util::combinators::BoxBody;
use hyper::body::Bytes;
use hyper::{Request, Response};
use tracing::instrument;

use crate::error::Error;
use crate::GatewayUri;

#[cfg(feature = "connect-bootstrap")]
pub mod connect;

#[cfg(feature = "ws-bootstrap")]
pub mod ws;

#[instrument(skip(req))]
pub(crate) async fn handle_ohttp_keys<B>(
    req: Request<B>,
    gateway_origin: GatewayUri,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Error>
where
    B: Send + 'static,
{
    #[cfg(feature = "connect-bootstrap")]
    if connect::is_connect_request(&req) {
        return connect::try_upgrade(req, gateway_origin).await;
    }

    #[cfg(feature = "ws-bootstrap")]
    if ws::is_websocket_request(&req) {
        return ws::try_upgrade(req, gateway_origin).await;
    }

    Err(Error::BadRequest("Not a supported proxy upgrade request".to_string()))
}
