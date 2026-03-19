//! Async callback wrappers for receiver checklist.
//!
//! The core payjoin library takes synchronous closures for receiver
//! validation callbacks (broadcast checking, script ownership, etc.).
//! Languages like Dart are inherently async and cannot block inside a
//! sync callback to perform wallet or network operations.
//!
//! This module provides async trait alternatives for each callback.
//! The bridge methods accept an async callback and use
//! `block_in_place` + `Handle::current().block_on()` to drive the
//! future from within the core's sync closure.
//!
//! This is different from the `save_async` / persistence path. The
//! core library already exposes first-class async persistence via
//! `AsyncSessionPersister`, so `save_async` can be a true `async fn`
//! that awaits the persister directly—no bridging needed. Validation
//! callbacks, on the other hand, are consumed by core as `FnMut`
//! closures with no async variant, so we must bridge here in the FFI
//! layer.

use std::str::FromStr;
use std::sync::{Arc, RwLock};

use payjoin::bitcoin::psbt::Psbt;

use super::{
    MaybeInputsOwned, MaybeInputsOwnedTransition, MaybeInputsSeen, MaybeInputsSeenTransition,
    Monitor, MonitorTransition, OutputsUnknown, OutputsUnknownTransition, PlainOutPoint,
    ProvisionalProposal, ProvisionalProposalTransition, UncheckedOriginalPayload,
    UncheckedOriginalPayloadTransition,
};
use crate::error::{FfiValidationError, ForeignError, ImplementationError};
use crate::validation::validate_fee_rate_sat_per_kwu_opt;

fn block_on_async<F: std::future::Future>(f: F) -> F::Output {
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(f))
}

#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait CanBroadcastAsync: Send + Sync {
    async fn callback(&self, tx: Vec<u8>) -> Result<bool, ForeignError>;
}

#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait IsScriptOwnedAsync: Send + Sync {
    async fn callback(&self, script: Vec<u8>) -> Result<bool, ForeignError>;
}

#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait IsOutputKnownAsync: Send + Sync {
    async fn callback(&self, outpoint: PlainOutPoint) -> Result<bool, ForeignError>;
}

#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait ProcessPsbtAsync: Send + Sync {
    async fn callback(&self, psbt: String) -> Result<String, ForeignError>;
}

#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait TransactionExistsAsync: Send + Sync {
    async fn callback(&self, txid: String) -> Result<Option<Vec<u8>>, ForeignError>;
}

#[uniffi::export]
impl UncheckedOriginalPayload {
    pub fn check_broadcast_suitability_async(
        &self,
        min_fee_rate: Option<u64>,
        can_broadcast: Arc<dyn CanBroadcastAsync>,
    ) -> Result<UncheckedOriginalPayloadTransition, FfiValidationError> {
        let min_fee_rate = validate_fee_rate_sat_per_kwu_opt(min_fee_rate)?;
        Ok(UncheckedOriginalPayloadTransition(Arc::new(RwLock::new(Some(
            self.0.clone().check_broadcast_suitability(min_fee_rate, |transaction| {
                block_on_async(
                    can_broadcast
                        .callback(payjoin::bitcoin::consensus::encode::serialize(transaction)),
                )
                .map_err(|e| ImplementationError::new(e).into())
            }),
        )))))
    }
}

#[uniffi::export]
impl MaybeInputsOwned {
    pub fn check_inputs_not_owned_async(
        &self,
        is_owned: Arc<dyn IsScriptOwnedAsync>,
    ) -> MaybeInputsOwnedTransition {
        MaybeInputsOwnedTransition(Arc::new(RwLock::new(Some(
            self.0.clone().check_inputs_not_owned(&mut |input| {
                block_on_async(is_owned.callback(input.to_bytes()))
                    .map_err(|e| ImplementationError::new(e).into())
            }),
        ))))
    }
}

#[uniffi::export]
impl MaybeInputsSeen {
    pub fn check_no_inputs_seen_before_async(
        &self,
        is_known: Arc<dyn IsOutputKnownAsync>,
    ) -> MaybeInputsSeenTransition {
        MaybeInputsSeenTransition(Arc::new(RwLock::new(Some(
            self.0.clone().check_no_inputs_seen_before(&mut |outpoint| {
                block_on_async(is_known.callback(PlainOutPoint::from(*outpoint)))
                    .map_err(|e| ImplementationError::new(e).into())
            }),
        ))))
    }
}

#[uniffi::export]
impl OutputsUnknown {
    pub fn identify_receiver_outputs_async(
        &self,
        is_receiver_output: Arc<dyn IsScriptOwnedAsync>,
    ) -> OutputsUnknownTransition {
        OutputsUnknownTransition(Arc::new(RwLock::new(Some(
            self.0.clone().identify_receiver_outputs(&mut |input| {
                block_on_async(is_receiver_output.callback(input.to_bytes()))
                    .map_err(|e| ImplementationError::new(e).into())
            }),
        ))))
    }
}

#[uniffi::export]
impl ProvisionalProposal {
    pub fn finalize_proposal_async(
        &self,
        process_psbt: Arc<dyn ProcessPsbtAsync>,
    ) -> ProvisionalProposalTransition {
        ProvisionalProposalTransition(Arc::new(RwLock::new(Some(
            self.0.clone().finalize_proposal(|pre_processed| {
                let psbt = block_on_async(process_psbt.callback(pre_processed.to_string()))
                    .map_err(ImplementationError::new)?;
                Ok(Psbt::from_str(&psbt).map_err(ImplementationError::new)?)
            }),
        ))))
    }
}

#[uniffi::export]
impl Monitor {
    pub fn monitor_async(
        &self,
        transaction_exists: Arc<dyn TransactionExistsAsync>,
    ) -> MonitorTransition {
        MonitorTransition(Arc::new(RwLock::new(Some(self.0.clone().check_payment(|txid| {
            block_on_async(transaction_exists.callback(txid.to_string()))
                .and_then(|buf| buf.map(super::try_deserialize_tx).transpose())
                .map_err(|e| ImplementationError::new(e).into())
        })))))
    }
}
