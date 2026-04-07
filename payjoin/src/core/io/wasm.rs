//! WASM IO implementation.

use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use base64::engine::general_purpose;
use base64::Engine;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::StreamExt;
#[cfg(feature = "_manual-tls")]
use futures_rustls::pki_types::CertificateDer;
use gloo_net::websocket::futures::WebSocket;
use js_sys::{Promise, Reflect, Uint8Array};
use url::Url;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use super::Error;
use crate::{into_url, IntoUrl, OhttpKeys};

pub async fn fetch_ohttp_keys(
    ohttp_relay: impl IntoUrl,
    payjoin_directory: impl IntoUrl,
) -> Result<OhttpKeys, Error> {
    fetch_ohttp_keys_strategy(ohttp_relay, payjoin_directory, None).await
}

#[cfg(feature = "_manual-tls")]
pub async fn fetch_ohttp_keys_with_cert(
    ohttp_relay: impl IntoUrl,
    payjoin_directory: impl IntoUrl,
    cert_der: Vec<u8>,
) -> Result<OhttpKeys, Error> {
    fetch_ohttp_keys_strategy(ohttp_relay, payjoin_directory, Some(cert_der)).await
}

async fn fetch_ohttp_keys_strategy(
    relay: impl IntoUrl,
    directory: impl IntoUrl,
    cert: Option<Vec<u8>>,
) -> Result<OhttpKeys, Error> {
    let relay = relay.into_url()?;
    let directory = directory.into_url()?;
    let runtime = get_runtime_env();

    // if we're not running in a browser
    if !matches!(runtime, Runtime::BrowserMain | Runtime::WebWorker) {
        if let Ok(keys) = fetch_via_http_connect(&relay, &directory, cert.as_deref()).await {
            return Ok(keys);
        }
    }

    fetch_via_websocket(relay, directory, cert.as_deref()).await
}

// Helper macro to create JS objects, we can't use serde
// complex types in JS objects.
macro_rules! js_object {
    ($($key:expr => $val:expr),* $(,)?) => {{
        let obj = js_sys::Object::new();
        $(
            let _ = js_sys::Reflect::set(
                &obj,
                &wasm_bindgen::JsValue::from($key),
                &wasm_bindgen::JsValue::from($val)
            );
        )*
        obj
    }};
}

#[wasm_bindgen(module = "undici")]
extern "C" {
    #[wasm_bindgen(js_name = ProxyAgent)]
    type ProxyAgent;

    // ProxyAgent::new()
    #[wasm_bindgen(constructor, js_class = "ProxyAgent", catch)]
    fn new(options: &JsValue) -> Result<ProxyAgent, JsValue>;

    // undici::fetch()
    #[wasm_bindgen(js_name = fetch, catch)]
    fn fetch(url: &str, options: &JsValue) -> Result<Promise, JsValue>;

}

#[wasm_bindgen]
extern "C" {
    type Response;

    #[wasm_bindgen(method, structural, js_name = arrayBuffer)]
    fn array_buffer(this: &Response) -> Promise;
}

async fn fetch_via_http_connect(
    ohttp_relay: &Url,
    payjoin_directory: &Url,
    cert_der: Option<&[u8]>,
) -> Result<OhttpKeys, Error> {
    let directory_url = payjoin_directory.join("/.well-known/ohttp-gateway")?;

    let fetch_options = {
        let request_tls = if let Some(cert) = cert_der {
            js_object! {
                "ca" => serialize_der_to_pem(cert) // we end up not validating this unfortunately
            }
        } else {
            js_object! {}
        };

        let agent_options = js_object! {
            "uri" => ohttp_relay.as_str(), // proxy_url,
            "requestTls" => request_tls
        };

        let agent =
            ProxyAgent::new(&agent_options).map_err(InternalErrorInner::ProxyFetchFailed)?;

        let headers = js_object! {
            "Accept" => "application/ohttp-keys"
        };

        js_object! {
            "dispatcher" => agent,
            "headers" => headers
        }
    };

    let ohttp_key_bytes = {
        // call unidici fetch(), and jump through multiple hoops to get a Vec() out of the response
        // This can fail for a multitude of reasons, including:
        // 1. Invalid proxy (Some cases that could be categorized under BadUrl)
        // 2. Invalid certificate (Ideally we should throw BadCert but then we'd be
        //      unnecesarrily parsing the cert)
        // 3. Other network errors
        let response = fetch(directory_url.as_str(), &fetch_options)
            .map_err(InternalErrorInner::ProxyFetchFailed)?;
        let response =
            JsFuture::from(response).await.map_err(InternalErrorInner::ProxyFetchFailed)?;
        let response: Response = response.unchecked_into();
        Uint8Array::new(
            &JsFuture::from(response.array_buffer())
                .await
                .map_err(|_e| InternalErrorInner::InvalidResponse)?,
        )
        .to_vec()
    };

    OhttpKeys::decode(&ohttp_key_bytes).map_err(Error::from)
}

async fn fetch_via_websocket(
    ohttp_relay: Url,
    payjoin_directory: Url,
    _cert_der: Option<&[u8]>,
) -> Result<OhttpKeys, Error> {
    let tls_connector = {
        #[allow(unused_mut)]
        let mut root_store =
            rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };

        #[cfg(feature = "_manual-tls")]
        if let Some(cert) = _cert_der {
            root_store.add(CertificateDer::from_slice(cert))?
        }

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        futures_rustls::TlsConnector::from(Arc::new(config))
    };
    let directory_host = payjoin_directory
        .host_str()
        .ok_or_else(|| InternalErrorInner::BadUrl(url::ParseError::EmptyHost.into()))?;
    let directory_port = payjoin_directory.port_or_known_default();

    let domain = rustls::pki_types::ServerName::try_from(directory_host)
        .map_err(|_| InternalErrorInner::BadUrl(url::ParseError::IdnaError.into()))?
        .to_owned();

    let ws_scheme = match ohttp_relay.scheme() {
        "https" => "wss",
        _ => "ws",
    };

    let relay_host = ohttp_relay
        .host_str()
        .ok_or_else(|| InternalErrorInner::BadUrl(url::ParseError::EmptyHost.into()))?;

    let relay_port =
        ohttp_relay.port_or_known_default().unwrap_or(if ws_scheme == "wss" { 443 } else { 80 });

    let ws_url =
        format!("{}://{}:{}/{}", ws_scheme, relay_host, relay_port, payjoin_directory.as_str());

    let ws = WebSocket::open(&ws_url).map_err(|e| InternalErrorInner::WebSocketFailed(e))?;

    let mut tls_stream =
        tls_connector.connect(domain, ws).await.map_err(|_| InternalErrorInner::InvalidResponse)?;
    let host_header = match directory_port {
        Some(port) => format!("{}:{}", directory_host, port),
        None => directory_host.to_string(),
    };
    let ohttp_keys_req =
        format!("GET /ohttp-keys HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", host_header);
    tls_stream
        .write_all(ohttp_keys_req.as_bytes())
        .await
        .map_err(|_| InternalErrorInner::InvalidResponse)?;
    tls_stream.flush().await.map_err(|_| InternalErrorInner::InvalidResponse)?;
    let mut response_bytes = Vec::new();
    tls_stream
        .read_to_end(&mut response_bytes)
        .await
        .map_err(|_| InternalErrorInner::InvalidResponse)?;

    // Consume whatever remains in the WebSocket stream
    // necesarry, else the stream may try to call onmessage handlers
    // that have been dropped.
    let (mut ws, _tls_connection) = tls_stream.into_inner();
    while let Some(_) = ws.next().await {}

    let (_headers, res_body) = separate_headers_and_body(&response_bytes)?;
    OhttpKeys::decode(res_body).map_err(Error::from)
}

#[derive(Debug)]
pub(super) enum InternalErrorInner {
    BadUrl(into_url::Error),
    #[cfg(feature = "_manual-tls")]
    InvalidCert(rustls::Error),
    WebSocketFailed(gloo_utils::errors::JsError),
    ProxyFetchFailed(JsValue),
    InvalidResponse,
    OhttpDecodeFailed(ohttp::Error),
}

// Convert DER-encoded certificate bytes to a PEM-formatted certificate string.
// Wrap lines at 64 characters per PEM convention.
fn serialize_der_to_pem(cert_der: &[u8]) -> String {
    let b64 = general_purpose::STANDARD.encode(cert_der);
    let mut pem = String::with_capacity(b64.len() + 64);
    pem.push_str("-----BEGIN CERTIFICATE-----\n");
    // Insert line breaks every 64 chars
    for chunk in b64.as_bytes().chunks(64) {
        // Safe to unwrap: base64 output is valid ASCII
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----");
    pem
}

fn separate_headers_and_body(response_bytes: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let separator = b"\r\n\r\n";

    // Search for the separator
    if let Some(position) =
        response_bytes.windows(separator.len()).position(|window| window == separator)
    {
        // The body starts immediately after the separator
        let body_start_index = position + separator.len();
        let headers = &response_bytes[..position];
        let body = &response_bytes[body_start_index..];

        Ok((headers, body))
    } else {
        Err(InternalErrorInner::InvalidResponse.into())
    }
}
impl std::fmt::Display for InternalErrorInner {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidResponse => write!(f, "Request failed"),
            Self::BadUrl(e) => write!(f, "URL parse error: {e}"),
            Self::OhttpDecodeFailed(e) => write!(f, "Failed to decode OHTTP keys: {e}"),
            #[cfg(feature = "_manual-tls")]
            Self::InvalidCert(e) => write!(f, "Invalid certificate: {e}"),
            Self::WebSocketFailed(e) => write!(f, "WebSocket connection failed: {e}"),
            Self::ProxyFetchFailed(e) => write!(f, "Proxy fetch failed: {}", js_value_to_string(e)),
        }
    }
}

impl std::error::Error for InternalErrorInner {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidResponse => None,
            Self::BadUrl(e) => Some(e),
            Self::OhttpDecodeFailed(e) => Some(e),
            #[cfg(feature = "_manual-tls")]
            Self::InvalidCert(e) => Some(e),
            Self::WebSocketFailed(e) => Some(e),
            Self::ProxyFetchFailed(_) => None,
        }
    }
}

super::impl_from_error!(into_url::Error, BadUrl);
super::impl_from_error!(url::ParseError, BadUrl);
super::impl_from_error!(ohttp::Error, OhttpDecodeFailed);
#[cfg(feature = "_manual-tls")]
super::impl_from_error!(rustls::Error, InvalidCert);

fn js_value_to_string(value: &JsValue) -> String {
    if let Some(s) = value.as_string() {
        s
    } else if let Some(e) = value.dyn_ref::<js_sys::Error>() {
        String::from(e.to_string())
    } else {
        format!("{:?}", value)
    }
}

enum Runtime {
    BrowserMain,
    WebWorker,
    NodeJS,
    Unknown,
}

impl std::fmt::Display for Runtime {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Runtime::BrowserMain => write!(f, "BrowserMain"),
            Runtime::WebWorker => write!(f, "WebWorker"),
            Runtime::NodeJS => write!(f, "NodeJS"),
            Runtime::Unknown => write!(f, "Unknown"),
        }
    }
}

fn get_runtime_env() -> Runtime {
    let global = js_sys::global();

    // Bun and Deno are checked first as they both have the process global.
    if is_defined(&global, "process") {
        return Runtime::NodeJS;
    }

    if is_defined(&global, "window") && is_defined(&global, "document") {
        return Runtime::BrowserMain;
    }

    if is_defined(&global, "WorkerGlobalScope") || is_defined(&global, "importScripts") {
        return Runtime::WebWorker;
    }

    Runtime::Unknown
}

fn is_defined(global: &js_sys::Object, prop: &str) -> bool {
    // Using Reflect to check for properties on global, js_sys does not expose any
    // web/runtime APIs. However, Reflect is part of the ECMAScript standard
    match Reflect::get(global, &JsValue::from_str(prop)) {
        Ok(value) => !value.is_undefined() && !value.is_null(),
        Err(_) => false,
    }
}
