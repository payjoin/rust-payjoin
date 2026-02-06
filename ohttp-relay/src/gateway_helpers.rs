use std::io::Cursor;

pub const CHACHA20_POLY1305_NONCE_LEN: usize = 32;
pub const POLY1305_TAG_SIZE: usize = 16;
pub const ENCAPSULATED_MESSAGE_BYTES: usize = 65536;
pub const BHTTP_REQ_BYTES: usize =
    ENCAPSULATED_MESSAGE_BYTES - (CHACHA20_POLY1305_NONCE_LEN + POLY1305_TAG_SIZE);

#[derive(Debug)]
pub enum GatewayError {
    BadRequest(String),
    OhttpKeyRejection(String),
    InternalServerError(String),
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GatewayError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            GatewayError::OhttpKeyRejection(msg) => write!(f, "OHTTP key rejection: {}", msg),
            GatewayError::InternalServerError(msg) => write!(f, "Internal server error: {}", msg),
        }
    }
}

impl std::error::Error for GatewayError {}

/// Represents the decapsulated HTTP request extracted from OHTTP
pub struct DecapsulatedRequest {
    pub method: String,
    pub uri: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub fn decapsulate_ohttp_request(
    ohttp_body: &[u8],
    ohttp_server: &ohttp::Server,
) -> Result<(DecapsulatedRequest, ohttp::ServerResponse), GatewayError> {
    let (bhttp_req, res_ctx) = ohttp_server.decapsulate(ohttp_body).map_err(|e| {
        GatewayError::OhttpKeyRejection(format!("OHTTP decapsulation failed: {}", e))
    })?;

    let mut cursor = Cursor::new(bhttp_req);
    let bhttp_msg = bhttp::Message::read_bhttp(&mut cursor)
        .map_err(|e| GatewayError::BadRequest(format!("Invalid BHTTP: {}", e)))?;

    let method = String::from_utf8(bhttp_msg.control().method().unwrap_or_default().to_vec())
        .unwrap_or_else(|_| "GET".to_string());

    let uri = format!(
        "{}://{}{}",
        std::str::from_utf8(bhttp_msg.control().scheme().unwrap_or_default()).unwrap_or("https"),
        std::str::from_utf8(bhttp_msg.control().authority().unwrap_or_default())
            .unwrap_or("localhost"),
        std::str::from_utf8(bhttp_msg.control().path().unwrap_or_default()).unwrap_or("/")
    );

    let mut headers = Vec::new();
    for field in bhttp_msg.header().fields() {
        let name = String::from_utf8_lossy(field.name()).to_string();
        let value = String::from_utf8_lossy(field.value()).to_string();
        headers.push((name, value));
    }

    let body = bhttp_msg.content().to_vec();

    Ok((DecapsulatedRequest { method, uri, headers, body }, res_ctx))
}

pub fn encapsulate_ohttp_response(
    status_code: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    res_ctx: ohttp::ServerResponse,
) -> Result<Vec<u8>, GatewayError> {
    let bhttp_status = bhttp::StatusCode::try_from(status_code)
        .map_err(|e| GatewayError::InternalServerError(format!("Invalid status code: {}", e)))?;

    let mut bhttp_res = bhttp::Message::response(bhttp_status);

    for (name, value) in &headers {
        bhttp_res.put_header(name.as_str(), value.as_str());
    }

    bhttp_res.write_content(&body);

    let mut bhttp_bytes = Vec::new();
    bhttp_res.write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_bytes).map_err(|e| {
        GatewayError::InternalServerError(format!("BHTTP serialization failed: {}", e))
    })?;

    bhttp_bytes.resize(BHTTP_REQ_BYTES, 0);

    let ohttp_res = res_ctx.encapsulate(&bhttp_bytes).map_err(|e| {
        GatewayError::InternalServerError(format!("OHTTP encapsulation failed: {}", e))
    })?;

    assert!(
        ohttp_res.len() == ENCAPSULATED_MESSAGE_BYTES,
        "Unexpected OHTTP response size: {} != {}",
        ohttp_res.len(),
        ENCAPSULATED_MESSAGE_BYTES
    );

    Ok(ohttp_res)
}
