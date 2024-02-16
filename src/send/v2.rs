use std::io::Cursor;
use std::sync::Mutex;

use crate::error::PayjoinError;

pub struct ContextV2(Mutex<Option<payjoin::send::ContextV2>>);
impl From<&ContextV2> for payjoin::send::ContextV2 {
    fn from(value: &ContextV2) -> Self {
        let mut data_guard = value.0.lock().unwrap();
        Option::take(&mut *data_guard).expect("ContextV2 moved out of memory")
    }
}
impl From<payjoin::send::ContextV2> for ContextV2 {
    fn from(value: payjoin::send::ContextV2) -> Self {
        Self(Mutex::new(Some(value)))
    }
}
impl ContextV2 {
    ///Decodes and validates the response.
    /// Call this method with response from receiver to continue BIP-??? flow. A successful response can either be None if the relay has not response yet or Some(Psbt).
    /// If the response is some valid PSBT you should sign and broadcast.
    pub fn process_response(&self, response: Vec<u8>) -> Result<Option<String>, PayjoinError> {
        let mut decoder = Cursor::new(response);
        <&ContextV2 as Into<payjoin::send::ContextV2>>::into(self)
            .process_response(&mut decoder)
            .map(|e| e.map(|o| o.to_string()))
            .map_err(|e| e.into())
    }
}
