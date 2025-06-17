use std::fmt::{self, Display};

use url::Url;

use super::{Sender, WithReplyKey};
use crate::persist::Value;
use crate::send::v2::V2GetContext;

/// Opaque key type for the sender
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderToken(pub(crate) Url);

impl Display for SenderToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

impl From<Sender<WithReplyKey>> for SenderToken {
    fn from(sender: Sender<WithReplyKey>) -> Self { SenderToken(sender.endpoint().clone()) }
}

impl AsRef<[u8]> for SenderToken {
    fn as_ref(&self) -> &[u8] { self.0.as_str().as_bytes() }
}

impl Value for Sender<WithReplyKey> {
    type Key = SenderToken;

    fn key(&self) -> Self::Key { SenderToken(self.endpoint().clone()) }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SessionEvent {
    /// Sender was created with a HPKE key pair
    CreatedReplyKey(WithReplyKey),
    /// Sender POST'd the original PSBT, and waiting to receive a Proposal PSBT using GET context
    V2GetContext(V2GetContext),
    /// Sender received a Proposal PSBT
    ProposalReceived(bitcoin::Psbt),
    /// Invalid session
    SessionInvalid(String),
}

#[cfg(test)]
mod tests {
    use bitcoin::{FeeRate, ScriptBuf};
    use payjoin_test_utils::PARSED_ORIGINAL_PSBT;

    use super::*;
    use crate::send::v2::HpkeContext;
    use crate::send::{v1, PsbtContext};
    use crate::{HpkeKeyPair, OutputSubstitution};

    #[test]
    fn test_sender_session_event_serialization_roundtrip() {
        let endpoint = Url::parse("http://localhost:1234").expect("Valid URL");
        let keypair = HpkeKeyPair::gen_keypair();
        let sender_with_reply_key = WithReplyKey {
            v1: v1::Sender {
                psbt: PARSED_ORIGINAL_PSBT.clone(),
                endpoint: endpoint.clone(),
                output_substitution: OutputSubstitution::Enabled,
                fee_contribution: None,
                min_fee_rate: FeeRate::ZERO,
                payee: ScriptBuf::from(vec![0x00]),
            },
            reply_key: keypair.0.clone(),
        };

        let v2_get_context = V2GetContext {
            endpoint,
            psbt_ctx: PsbtContext {
                original_psbt: PARSED_ORIGINAL_PSBT.clone(),
                output_substitution: OutputSubstitution::Enabled,
                fee_contribution: None,
                min_fee_rate: FeeRate::ZERO,
                payee: ScriptBuf::from(vec![0x00]),
            },
            hpke_ctx: HpkeContext { receiver: keypair.clone().1, reply_pair: keypair },
        };

        let test_cases = vec![
            SessionEvent::CreatedReplyKey(sender_with_reply_key.clone()),
            SessionEvent::V2GetContext(v2_get_context.clone()),
            SessionEvent::ProposalReceived(PARSED_ORIGINAL_PSBT.clone()),
            SessionEvent::SessionInvalid("error message".to_string()),
        ];

        for event in test_cases {
            let serialized = serde_json::to_string(&event).expect("Should serialize");
            let deserialized: SessionEvent =
                serde_json::from_str(&serialized).expect("Should deserialize");
            assert_eq!(event, deserialized);
        }
    }
}
