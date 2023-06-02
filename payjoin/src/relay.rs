
use std::borrow::Cow;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub body: Vec<u8>,
    pub query: String,
    #[serde(deserialize_with = "hyper_serde::deserialize", serialize_with = "hyper_serde::serialize")]
    pub headers: hyper::HeaderMap,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response<'a> {
    pub body: Vec<u8>,
    pub headers: VecHeaders<'a>,
    pub status_code: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VecHeaders<'a>(Vec<(Cow<'a, str>, Cow<'a, str>)>);

impl<'a> VecHeaders<'a> {
    pub fn new(headers: Vec<(Cow<'a, str>, Cow<'a, str>)>) -> Self { Self(headers) }
}

impl crate::receive::Headers for VecHeaders<'_> {
    fn get_header(&self, key: &str) -> Option<&str> {
        log::debug!("get_header({})", key);
        self.0.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v.as_ref())
    }
}