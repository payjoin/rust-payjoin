use std::borrow::Cow;

use bitcoin::base64;
use bitcoin::secp256k1::PublicKey;
use url::Url;

use crate::uri::error::SubdirParseError;
use crate::OhttpKeys;

/// Parse and set fragment parameters from `&pj=` URLs
pub(crate) trait PjUrlExt {
    fn subdirectory_pubkey(&self) -> Result<PublicKey, SubdirParseError>;
    fn ohttp(&self) -> Option<OhttpKeys>;
    fn set_ohttp(&mut self, ohttp: Option<OhttpKeys>);
}

impl PjUrlExt for Url {
    fn subdirectory_pubkey(&self) -> Result<bitcoin::secp256k1::PublicKey, SubdirParseError> {
        let subdirectory = self
            .path_segments()
            .ok_or(SubdirParseError::MissingSubdirectory)?
            .next()
            .ok_or(SubdirParseError::MissingSubdirectory)?
            .to_string();

        let pubkey_bytes = base64::decode_config(subdirectory, base64::URL_SAFE_NO_PAD)
            .map_err(SubdirParseError::SubdirectoryNotBase64)?;
        bitcoin::secp256k1::PublicKey::from_slice(&pubkey_bytes)
            .map_err(SubdirParseError::SubdirectoryInvalidPubkey)
    }

    fn ohttp(&self) -> Option<OhttpKeys> {
        self.fragment().and_then(|f| {
            let parts: Vec<&str> = f.splitn(2, "ohttp=").collect();
            if parts.len() == 2 {
                let base64_config = Cow::from(parts[1]);
                let config_bytes =
                    base64::decode_config(&*base64_config, base64::URL_SAFE_NO_PAD).ok()?;
                OhttpKeys::decode(&config_bytes).ok()
            } else {
                None
            }
        })
    }

    fn set_ohttp(&mut self, ohttp: Option<OhttpKeys>) {
        if let Some(ohttp) = ohttp {
            let new_ohttp = format!("ohttp={}", ohttp);
            let mut fragment = self.fragment().unwrap_or("").to_string();
            if let Some(start) = fragment.find("ohttp=") {
                let end = fragment[start..].find('&').map_or(fragment.len(), |i| start + i);
                fragment.replace_range(start..end, &new_ohttp);
            } else {
                if !fragment.is_empty() {
                    fragment.push('&');
                }
                fragment.push_str(&new_ohttp);
            }
            self.set_fragment(Some(&fragment));
        }
    }
}
