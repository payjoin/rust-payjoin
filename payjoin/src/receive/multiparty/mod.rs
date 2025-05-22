use bitcoin::{FeeRate, Psbt};
use error::IdenticalProposalError;
pub use session::ReceiverSessionEvent;

use super::error::InputContributionError;
use super::{v1, v2, Error, InputPair, ReplyableError};
use crate::persist::{
    MaybeBadInitInputsTransition, MaybeFatalTransition,
    MaybeSuccessTransition, MaybeTransientTransition, NextStateTransition,
};
use crate::psbt::merge::merge_unsigned_tx;
use crate::receive::multiparty::error::{InternalMultipartyError, MultipartyError};
use crate::receive::v2::SessionContext;
use crate::{ImplementationError, Version};

pub(crate) mod error;
pub(crate) mod session;

const SUPPORTED_VERSIONS: &[Version] = &[Version::Two];

#[derive(Default)]
pub struct UncheckedProposalBuilder {
    proposals: Vec<v2::UncheckedProposal>,
}

impl UncheckedProposalBuilder {
    pub fn new() -> Self { Self { proposals: vec![] } }

    pub fn add(&mut self, proposal: v2::UncheckedProposal) -> Result<Self, MultipartyError> {
        self.check_proposal_suitability(&proposal)?;
        self.proposals.push(proposal);
        Ok(Self { proposals: self.proposals.clone() })
    }

    fn check_proposal_suitability(
        &self,
        proposal: &v2::UncheckedProposal,
    ) -> Result<(), MultipartyError> {
        let params = proposal.v1.params.clone();
        if !SUPPORTED_VERSIONS.contains(&params.v) {
            return Err(InternalMultipartyError::ProposalVersionNotSupported(params.v).into());
        }

        if !params.optimistic_merge {
            return Err(InternalMultipartyError::OptimisticMergeNotSupported.into());
        }

        if let Some(duplicate_context) =
            self.proposals.iter().find(|c| c.context == proposal.context)
        {
            return Err(InternalMultipartyError::IdenticalProposals(
                IdenticalProposalError::IdenticalContexts(
                    Box::new(duplicate_context.context.id()),
                    Box::new(proposal.context.id()),
                ),
            )
            .into());
        };

        if let Some(duplicate_psbt) =
            self.proposals.iter().find(|psbt| psbt.v1.psbt == proposal.v1.psbt)
        {
            return Err(InternalMultipartyError::IdenticalProposals(
                IdenticalProposalError::IdenticalPsbts(
                    Box::new(duplicate_psbt.v1.psbt.clone()),
                    Box::new(proposal.v1.psbt.clone()),
                ),
            )
            .into());
        }
        Ok(())
    }

    pub fn build(
        &self,
    ) -> MaybeBadInitInputsTransition<
        ReceiverSessionEvent,
        Receiver<UncheckedProposal>,
        MultipartyError,
    > {
        if self.proposals.len() < 2 {
            return MaybeBadInitInputsTransition::bad_init_inputs(
                InternalMultipartyError::NotEnoughProposals.into(),
            );
        }
        let agg_psbt = match self
            .proposals
            .iter()
            .map(|p| p.v1.psbt.clone())
            .reduce(merge_unsigned_tx)
            .ok_or(InternalMultipartyError::NotEnoughProposals)
        {
            Ok(agg_psbt) => agg_psbt,
            Err(e) => return MaybeBadInitInputsTransition::bad_init_inputs(e.into()),
        };
        let unchecked_proposal = v1::UncheckedProposal {
            psbt: agg_psbt,
            params: self.proposals.first().expect("checked above").v1.params.clone(),
        };
        let contexts = self.proposals.iter().map(|p| p.context.clone()).collect();
        let new_state = UncheckedProposal { v1: unchecked_proposal, contexts };

        // TODO: from here on, we don't need to persist events for the v2::receiver
        // The v2 session has not been upgraded to a NS1R session. This state transition need to be one that closes the other sessions
        MaybeBadInitInputsTransition::success(
            ReceiverSessionEvent::UncheckedProposal(new_state.clone()),
            Receiver { state: new_state },
        )
    }
}

pub struct Receiver<State> {
    state: State,
}

/// A multiparty proposal that has been merged by the receiver
#[derive(Clone)]
pub struct UncheckedProposal {
    v1: v1::UncheckedProposal,
    contexts: Vec<SessionContext>,
}

impl Receiver<UncheckedProposal> {
    pub fn check_broadcast_suitability(
        self,
        min_fee_rate: Option<FeeRate>,
        can_broadcast: impl Fn(&bitcoin::Transaction) -> Result<bool, ImplementationError>,
    ) -> MaybeFatalTransition<ReceiverSessionEvent, Receiver<MaybeInputsOwned>, Error> {
        let inner = match self.state.v1.check_broadcast_suitability(min_fee_rate, can_broadcast) {
            Ok(inner) => inner,
            Err(e) => match e {
                ReplyableError::Implementation(_) =>
                    return MaybeFatalTransition::transient(e.into()),
                _ =>
                    return MaybeFatalTransition::fatal(
                        ReceiverSessionEvent::SessionInvalid(e.to_string()),
                        e.into(),
                    ),
            },
        };
        let new_state = MaybeInputsOwned { v1: inner, contexts: self.state.contexts };
        MaybeFatalTransition::success(
            ReceiverSessionEvent::MaybeInputsOwned(new_state.clone()),
            Receiver { state: new_state },
        )
    }
}

#[derive(Clone)]
pub struct MaybeInputsOwned {
    v1: v1::MaybeInputsOwned,
    contexts: Vec<SessionContext>,
}

impl Receiver<MaybeInputsOwned> {
    pub fn check_inputs_not_owned(
        self,
        is_owned: impl Fn(&bitcoin::Script) -> Result<bool, ImplementationError>,
    ) -> MaybeFatalTransition<ReceiverSessionEvent, Receiver<MaybeInputsSeen>, Error> {
        let inner = match self.state.v1.check_inputs_not_owned(is_owned) {
            Ok(inner) => inner,
            Err(e) => match e {
                ReplyableError::Implementation(_) =>
                    return MaybeFatalTransition::transient(e.into()),
                _ =>
                    return MaybeFatalTransition::fatal(
                        ReceiverSessionEvent::SessionInvalid(e.to_string()),
                        e.into(),
                    ),
            },
        };
        let new_state = MaybeInputsSeen { v1: inner, contexts: self.state.contexts };
        MaybeFatalTransition::success(
            ReceiverSessionEvent::MaybeInputsSeen(new_state.clone()),
            Receiver { state: new_state },
        )
    }
}

#[derive(Clone)]
pub struct MaybeInputsSeen {
    v1: v1::MaybeInputsSeen,
    contexts: Vec<SessionContext>,
}

impl Receiver<MaybeInputsSeen> {
    pub fn check_no_inputs_seen_before(
        self,
        is_seen: impl Fn(&bitcoin::OutPoint) -> Result<bool, ImplementationError>,
    ) -> MaybeFatalTransition<ReceiverSessionEvent, Receiver<OutputsUnknown>, Error> {
        let inner = match self.state.v1.check_no_inputs_seen_before(is_seen) {
            Ok(inner) => inner,
            Err(e) => match e {
                ReplyableError::Implementation(_) =>
                    return MaybeFatalTransition::transient(e.into()),
                _ =>
                    return MaybeFatalTransition::fatal(
                        ReceiverSessionEvent::SessionInvalid(e.to_string()),
                        e.into(),
                    ),
            },
        };
        let new_state = OutputsUnknown { v1: inner, contexts: self.state.contexts };
        MaybeFatalTransition::success(
            ReceiverSessionEvent::OutputsUnknown(new_state.clone()),
            Receiver { state: new_state },
        )
    }
}

#[derive(Clone)]
pub struct OutputsUnknown {
    v1: v1::OutputsUnknown,
    contexts: Vec<SessionContext>,
}

impl Receiver<OutputsUnknown> {
    pub fn identify_receiver_outputs(
        self,
        is_receiver_output: impl Fn(&bitcoin::Script) -> Result<bool, ImplementationError>,
    ) -> MaybeFatalTransition<ReceiverSessionEvent, Receiver<WantsOutputs>, Error> {
        let inner = match self.state.v1.identify_receiver_outputs(is_receiver_output) {
            Ok(inner) => inner,
            Err(e) => match e {
                ReplyableError::Implementation(_) =>
                    return MaybeFatalTransition::transient(e.into()),
                _ =>
                    return MaybeFatalTransition::fatal(
                        ReceiverSessionEvent::SessionInvalid(e.to_string()),
                        e.into(),
                    ),
            },
        };
        let new_state = WantsOutputs { v1: inner, contexts: self.state.contexts };
        MaybeFatalTransition::success(
            ReceiverSessionEvent::WantsOutputs(new_state.clone()),
            Receiver { state: new_state },
        )
    }
}

#[derive(Clone)]
pub struct WantsOutputs {
    v1: v1::WantsOutputs,
    contexts: Vec<SessionContext>,
}

impl Receiver<WantsOutputs> {
    pub fn commit_outputs(
        self,
    ) -> NextStateTransition<ReceiverSessionEvent, Receiver<WantsInputs>> {
        let inner = self.state.v1.commit_outputs();
        let new_state = WantsInputs { v1: inner, contexts: self.state.contexts };
        NextStateTransition::success(
            ReceiverSessionEvent::WantsInputs(new_state.clone()),
            Receiver { state: new_state },
        )
    }
}

#[derive(Clone)]
pub struct WantsInputs {
    v1: v1::WantsInputs,
    contexts: Vec<SessionContext>,
}

impl Receiver<WantsInputs> {
    /// Add the provided list of inputs to the transaction.
    /// Any excess input amount is added to the change_vout output indicated previously.
    pub fn contribute_inputs(
        self,
        inputs: impl IntoIterator<Item = InputPair>,
    ) -> Result<Receiver<WantsInputs>, InputContributionError> {
        let inner = self.state.v1.contribute_inputs(inputs)?;
        let new_state = WantsInputs { v1: inner, contexts: self.state.contexts };
        Ok(Receiver { state: new_state })
    }

    /// Proceed to the proposal finalization step.
    /// Inputs cannot be modified after this function is called.
    pub fn commit_inputs(
        self,
    ) -> NextStateTransition<ReceiverSessionEvent, Receiver<ProvisionalProposal>> {
        let inner = self.state.v1.commit_inputs();
        let new_state = ProvisionalProposal { v1: inner, contexts: self.state.contexts };
        NextStateTransition::success(
            ReceiverSessionEvent::ProvisionalProposal(new_state.clone()),
            Receiver { state: new_state },
        )
    }
}

#[derive(Clone)]
pub struct ProvisionalProposal {
    v1: v1::ProvisionalProposal,
    contexts: Vec<SessionContext>,
}

impl Receiver<ProvisionalProposal> {
    pub fn finalize_proposal(
        self,
        wallet_process_psbt: impl Fn(&Psbt) -> Result<Psbt, ImplementationError>,
        min_feerate_sat_per_vb: Option<FeeRate>,
        max_feerate_sat_per_vb: FeeRate,
    ) -> MaybeTransientTransition<ReceiverSessionEvent, Receiver<PayjoinProposal>, ReplyableError>
    {
        let inner = match self.state.v1.finalize_proposal(
            wallet_process_psbt,
            min_feerate_sat_per_vb,
            Some(max_feerate_sat_per_vb),
        ) {
            Ok(inner) => inner,
            Err(e) => return MaybeTransientTransition::transient(e),
        };
        let new_state = PayjoinProposal { v1: inner, contexts: self.state.contexts };
        MaybeTransientTransition::success(
            ReceiverSessionEvent::PayjoinProposal(new_state.clone()),
            Receiver { state: new_state },
        )
    }
}

#[derive(Clone)]
pub struct PayjoinProposal {
    v1: v1::PayjoinProposal,
    contexts: Vec<SessionContext>,
}

impl Receiver<PayjoinProposal> {
    pub fn sender_iter(&self) -> impl Iterator<Item = v2::PayjoinProposal> {
        self.state
            .contexts
            .iter()
            .map(|ctx| v2::PayjoinProposal::new(self.state.v1.clone(), ctx.clone()))
            .collect::<Vec<_>>()
            .into_iter()
    }

    pub fn proposal(&self) -> &v1::PayjoinProposal { &self.state.v1 }
}

/// A multiparty proposal that is ready to be combined into a single psbt
#[derive(Default)]
pub struct FinalizedProposal {
    v2_proposals: Vec<v2::UncheckedProposal>,
}

impl FinalizedProposal {
    pub fn new() -> Self { Self { v2_proposals: vec![] } }

    pub fn add(&mut self, proposal: v2::UncheckedProposal) -> Result<(), MultipartyError> {
        self.check_proposal_suitability(&proposal)?;
        self.v2_proposals.push(proposal);
        Ok(())
    }

    fn check_proposal_suitability(
        &self,
        proposal: &v2::UncheckedProposal,
    ) -> Result<(), MultipartyError> {
        if !SUPPORTED_VERSIONS.contains(&proposal.v1.params.v) {
            return Err(
                InternalMultipartyError::ProposalVersionNotSupported(proposal.v1.params.v).into()
            );
        }
        if let Some(duplicate_context) =
            self.v2_proposals.iter().find(|c| c.context == proposal.context)
        {
            return Err(InternalMultipartyError::IdenticalProposals(
                IdenticalProposalError::IdenticalContexts(
                    Box::new(duplicate_context.context.id()),
                    Box::new(proposal.context.id()),
                ),
            )
            .into());
        };

        if let Some(duplicate_psbt) =
            self.v2_proposals.iter().find(|psbt| psbt.v1.psbt == proposal.v1.psbt)
        {
            return Err(InternalMultipartyError::IdenticalProposals(
                IdenticalProposalError::IdenticalPsbts(
                    Box::new(duplicate_psbt.v1.psbt.clone()),
                    Box::new(proposal.v1.psbt.clone()),
                ),
            )
            .into());
        }
        Ok(())
    }

    pub fn combine(self) -> MaybeSuccessTransition<Psbt, MultipartyError> {
        if self.v2_proposals.len() < 2 {
            return MaybeSuccessTransition::transient(
                InternalMultipartyError::NotEnoughProposals.into(),
            );
        }

        let mut agg_psbt = self.v2_proposals.first().expect("checked above").v1.psbt.clone();
        for proposal in self.v2_proposals.iter().skip(1) {
            match agg_psbt.combine(proposal.v1.psbt.clone()) {
                Ok(_) => (),
                Err(e) =>
                    return MaybeSuccessTransition::transient(
                        InternalMultipartyError::FailedToCombinePsbts(e).into(),
                    ),
            };
        }

        // We explicitly call extract_tx to do some fee sanity checks
        // Otherwise you can just read the inputs from the unsigned_tx of the psbt
        let tx = match agg_psbt.clone().extract_tx() {
            Ok(tx) => tx,
            Err(e) =>
                return MaybeSuccessTransition::transient(
                    InternalMultipartyError::BitcoinExtractTxError(Box::new(e)).into(),
                ),
        };

        if tx.input.iter().any(|input| input.witness.is_empty() && input.script_sig.is_empty()) {
            return MaybeSuccessTransition::transient(
                InternalMultipartyError::InputMissingWitnessOrScriptSig.into(),
            );
        }

        MaybeSuccessTransition::success(agg_psbt)
    }

    pub fn v2(&self) -> &[v2::UncheckedProposal] { &self.v2_proposals }
}

#[cfg(test)]
mod test {

    use std::any::{Any, TypeId};
    use std::str::FromStr;

    use bitcoin::Psbt;
    use payjoin_test_utils::{
        BoxError, MULTIPARTY_ORIGINAL_PSBT_ONE, MULTIPARTY_ORIGINAL_PSBT_TWO,
    };

    use super::error::IdenticalProposalError;
    use super::session::ReceiverSessionEvent;
    use super::{
        v1, v2, FinalizedProposal, InternalMultipartyError, MultipartyError,
        UncheckedProposalBuilder, SUPPORTED_VERSIONS,
    };
    use crate::persist::NoopPersister;
    use crate::receive::optional_parameters::Params;
    use crate::receive::v2::test::{SHARED_CONTEXT, SHARED_CONTEXT_TWO};

    fn multiparty_proposals() -> Vec<v1::UncheckedProposal> {
        let pairs = url::form_urlencoded::parse("v=2&optimisticmerge=true".as_bytes());
        let params = Params::from_query_pairs(pairs, SUPPORTED_VERSIONS)
            .expect("Could not parse from query pairs");

        [MULTIPARTY_ORIGINAL_PSBT_ONE, MULTIPARTY_ORIGINAL_PSBT_TWO]
            .iter()
            .map(|psbt_str| v1::UncheckedProposal {
                psbt: Psbt::from_str(psbt_str).expect("known psbt should parse"),
                params: params.clone(),
            })
            .collect()
    }

    #[test]
    fn test_single_context_multiparty() -> Result<(), BoxError> {
        let noop_persister = NoopPersister::<ReceiverSessionEvent>::default();
        let proposal_one = v2::UncheckedProposal {
            v1: multiparty_proposals()[0].clone(),
            context: SHARED_CONTEXT.clone(),
        };
        let mut multiparty = UncheckedProposalBuilder::new();
        multiparty.add(proposal_one)?;
        match multiparty.build().save(&noop_persister) {
            Ok(_) => panic!("multiparty has two identical participants and should error"),
            Err(e) => assert_eq!(
                e.api_error().expect("should be api error").to_string(),
                MultipartyError::from(InternalMultipartyError::NotEnoughProposals).to_string()
            ),
        }
        Ok(())
    }

    #[test]
    fn test_duplicate_context_multiparty() -> Result<(), BoxError> {
        let proposal_one = v2::UncheckedProposal {
            v1: multiparty_proposals()[0].clone(),
            context: SHARED_CONTEXT.clone(),
        };
        let proposal_two = v2::UncheckedProposal {
            v1: multiparty_proposals()[1].clone(),
            context: SHARED_CONTEXT.clone(),
        };
        let mut multiparty = UncheckedProposalBuilder::new().add(proposal_one.clone())?;
        match multiparty.add(proposal_two.clone()) {
            Ok(_) => panic!("multiparty has two identical contexts and should error"),
            Err(e) => assert_eq!(
                e.to_string(),
                MultipartyError::from(InternalMultipartyError::IdenticalProposals(
                    IdenticalProposalError::IdenticalContexts(
                        Box::new(proposal_one.context.id()),
                        Box::new(proposal_two.context.id())
                    )
                ))
                .to_string()
            ),
        }
        Ok(())
    }

    #[test]
    fn test_duplicate_psbt_multiparty() -> Result<(), BoxError> {
        let proposal_one = v2::UncheckedProposal {
            v1: multiparty_proposals()[0].clone(),
            context: SHARED_CONTEXT.clone(),
        };
        let proposal_two = v2::UncheckedProposal {
            v1: multiparty_proposals()[0].clone(),
            context: SHARED_CONTEXT_TWO.clone(),
        };
        let mut multiparty = UncheckedProposalBuilder::new().add(proposal_one.clone())?;
        match multiparty.add(proposal_two.clone()) {
            Ok(_) => panic!("multiparty has two identical psbts and should error"),
            Err(e) => assert_eq!(
                e.to_string(),
                MultipartyError::from(InternalMultipartyError::IdenticalProposals(
                    IdenticalProposalError::IdenticalPsbts(
                        Box::new(proposal_one.v1.psbt),
                        Box::new(proposal_two.v1.psbt)
                    )
                ))
                .to_string()
            ),
        }
        Ok(())
    }

    #[test]
    fn finalize_multiparty() -> Result<(), BoxError> {
        use crate::psbt::PsbtExt;
        let noop_persister = NoopPersister::<ReceiverSessionEvent>::default();
        let proposal_one = v2::UncheckedProposal {
            v1: multiparty_proposals()[0].clone(),
            context: SHARED_CONTEXT.clone(),
        };
        let proposal_two = v2::UncheckedProposal {
            v1: multiparty_proposals()[1].clone(),
            context: SHARED_CONTEXT_TWO.clone(),
        };
        let mut finalized_multiparty = FinalizedProposal::new();
        finalized_multiparty.add(proposal_one)?;
        assert_eq!(finalized_multiparty.v2()[0].type_id(), TypeId::of::<v2::UncheckedProposal>());

        finalized_multiparty.add(proposal_two)?;
        assert_eq!(finalized_multiparty.v2()[1].type_id(), TypeId::of::<v2::UncheckedProposal>());

        let multiparty_psbt = match finalized_multiparty.combine().save(&noop_persister) {
            Ok(multiparty_psbt) => multiparty_psbt,
            Err(e) => {
                panic!("could not create PSBT from finalized proposal: {}", e);
            }
        };
        assert!(multiparty_psbt.validate_input_utxos().is_ok());
        Ok(())
    }
}
