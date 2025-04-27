use bitcoin::{FeeRate, Psbt};

use super::error::InputContributionError;
use super::{v1, v2, Error, InputPair};
use crate::psbt::merge::merge_unsigned_tx;
use crate::receive::multiparty::error::{InternalMultipartyError, MultipartyError};
use crate::receive::v2::SessionContext;
use crate::ImplementationError;

pub(crate) mod error;

const SUPPORTED_VERSIONS: &[usize] = &[2];

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
        Ok(())
    }

    pub fn build(&self) -> Result<UncheckedProposal, MultipartyError> {
        if self.proposals.len() < 2 {
            return Err(InternalMultipartyError::NotEnoughProposals.into());
        }
        let agg_psbt = self
            .proposals
            .iter()
            .map(|p| p.v1.psbt.clone())
            .reduce(merge_unsigned_tx)
            .ok_or(InternalMultipartyError::NotEnoughProposals)?;
        let unchecked_proposal = v1::UncheckedProposal {
            psbt: agg_psbt,
            params: self.proposals.first().expect("checked above").v1.params.clone(),
        };
        let contexts = self.proposals.iter().map(|p| p.context.clone()).collect();
        Ok(UncheckedProposal { v1: unchecked_proposal, contexts })
    }
}

/// A multiparty proposal that has been merged by the receiver
pub struct UncheckedProposal {
    v1: v1::UncheckedProposal,
    contexts: Vec<SessionContext>,
}

impl UncheckedProposal {
    pub fn check_broadcast_suitability(
        self,
        min_fee_rate: Option<FeeRate>,
        can_broadcast: impl Fn(&bitcoin::Transaction) -> Result<bool, ImplementationError>,
    ) -> Result<MaybeInputsOwned, Error> {
        let inner = self.v1.check_broadcast_suitability(min_fee_rate, can_broadcast)?;
        Ok(MaybeInputsOwned { v1: inner, contexts: self.contexts })
    }
}

pub struct MaybeInputsOwned {
    v1: v1::MaybeInputsOwned,
    contexts: Vec<SessionContext>,
}

impl MaybeInputsOwned {
    pub fn check_inputs_not_owned(
        self,
        is_owned: impl Fn(&bitcoin::Script) -> Result<bool, ImplementationError>,
    ) -> Result<MaybeInputsSeen, Error> {
        let inner = self.v1.check_inputs_not_owned(is_owned)?;
        Ok(MaybeInputsSeen { v1: inner, contexts: self.contexts })
    }
}

pub struct MaybeInputsSeen {
    v1: v1::MaybeInputsSeen,
    contexts: Vec<SessionContext>,
}

impl MaybeInputsSeen {
    pub fn check_no_inputs_seen_before(
        self,
        is_seen: impl Fn(&bitcoin::OutPoint) -> Result<bool, ImplementationError>,
    ) -> Result<OutputsUnknown, Error> {
        let inner = self.v1.check_no_inputs_seen_before(is_seen)?;
        Ok(OutputsUnknown { v1: inner, contexts: self.contexts })
    }
}

pub struct OutputsUnknown {
    v1: v1::OutputsUnknown,
    contexts: Vec<SessionContext>,
}

impl OutputsUnknown {
    pub fn identify_receiver_outputs(
        self,
        is_receiver_output: impl Fn(&bitcoin::Script) -> Result<bool, ImplementationError>,
    ) -> Result<WantsOutputs, Error> {
        let inner = self.v1.identify_receiver_outputs(is_receiver_output)?;
        Ok(WantsOutputs { v1: inner, contexts: self.contexts })
    }
}

pub struct WantsOutputs {
    v1: v1::WantsOutputs,
    contexts: Vec<SessionContext>,
}

impl WantsOutputs {
    pub fn commit_outputs(self) -> WantsInputs {
        let inner = self.v1.commit_outputs();
        WantsInputs { v1: inner, contexts: self.contexts }
    }
}

pub struct WantsInputs {
    v1: v1::WantsInputs,
    contexts: Vec<SessionContext>,
}

impl WantsInputs {
    /// Add the provided list of inputs to the transaction.
    /// Any excess input amount is added to the change_vout output indicated previously.
    pub fn contribute_inputs(
        self,
        inputs: impl IntoIterator<Item = InputPair>,
    ) -> Result<WantsInputs, InputContributionError> {
        let inner = self.v1.contribute_inputs(inputs)?;
        Ok(WantsInputs { v1: inner, contexts: self.contexts })
    }

    /// Proceed to the proposal finalization step.
    /// Inputs cannot be modified after this function is called.
    pub fn commit_inputs(self) -> ProvisionalProposal {
        let inner = self.v1.commit_inputs();
        ProvisionalProposal { v1: inner, contexts: self.contexts }
    }
}

pub struct ProvisionalProposal {
    v1: v1::ProvisionalProposal,
    contexts: Vec<SessionContext>,
}

impl ProvisionalProposal {
    pub fn finalize_proposal(
        self,
        wallet_process_psbt: impl Fn(&Psbt) -> Result<Psbt, ImplementationError>,
        min_feerate_sat_per_vb: Option<FeeRate>,
        max_feerate_sat_per_vb: FeeRate,
    ) -> Result<PayjoinProposal, Error> {
        let inner = self.v1.finalize_proposal(
            wallet_process_psbt,
            min_feerate_sat_per_vb,
            Some(max_feerate_sat_per_vb),
        )?;
        Ok(PayjoinProposal { v1: inner, contexts: self.contexts })
    }
}

pub struct PayjoinProposal {
    v1: v1::PayjoinProposal,
    contexts: Vec<SessionContext>,
}

impl PayjoinProposal {
    pub fn sender_iter(&self) -> impl Iterator<Item = v2::PayjoinProposal> {
        self.contexts
            .iter()
            .map(|ctx| v2::PayjoinProposal::new(self.v1.clone(), ctx.clone()))
            .collect::<Vec<_>>()
            .into_iter()
    }

    pub fn proposal(&self) -> &v1::PayjoinProposal { &self.v1 }
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
        Ok(())
    }

    pub fn combine(self) -> Result<Psbt, MultipartyError> {
        if self.v2_proposals.len() < 2 {
            return Err(InternalMultipartyError::NotEnoughProposals.into());
        }

        let mut agg_psbt = self.v2_proposals.first().expect("checked above").v1.psbt.clone();
        for proposal in self.v2_proposals.iter().skip(1) {
            agg_psbt
                .combine(proposal.v1.psbt.clone())
                .map_err(InternalMultipartyError::FailedToCombinePsbts)?;
        }

        // We explicitly call extract_tx to do some fee sanity checks
        // Otherwise you can just read the inputs from the unsigned_tx of the psbt
        let tx = agg_psbt
            .clone()
            .extract_tx()
            .map_err(|e| InternalMultipartyError::BitcoinExtractTxError(Box::new(e)))?;
        if tx.input.iter().any(|input| input.witness.is_empty() && input.script_sig.is_empty()) {
            return Err(InternalMultipartyError::InputMissingWitnessOrScriptSig.into());
        }

        Ok(agg_psbt)
    }

    pub fn v2(&self) -> &[v2::UncheckedProposal] { &self.v2_proposals }
}

#[cfg(test)]
mod test {

    use std::any::{Any, TypeId};

    use payjoin_test_utils::{BoxError, PARSED_ORIGINAL_PSBT};

    use super::{v1, v2, FinalizedProposal, UncheckedProposalBuilder, SUPPORTED_VERSIONS};
    use crate::receive::optional_parameters::Params;
    use crate::receive::v2::test::SHARED_CONTEXT;

    fn multiparty_proposal_from_test_vector() -> v1::UncheckedProposal {
        let pairs = url::form_urlencoded::parse("v=2&optimisticmerge=true".as_bytes());
        let params = Params::from_query_pairs(pairs, SUPPORTED_VERSIONS)
            .expect("Could not parse from query pairs");
        v1::UncheckedProposal { psbt: PARSED_ORIGINAL_PSBT.clone(), params }
    }

    #[test]
    fn test_build_multiparty() -> Result<(), BoxError> {
        let proposal_one = v2::UncheckedProposal {
            v1: multiparty_proposal_from_test_vector(),
            context: SHARED_CONTEXT.clone(),
        };
        let proposal_two = v2::UncheckedProposal {
            v1: multiparty_proposal_from_test_vector(),
            context: SHARED_CONTEXT.clone(),
        };
        let mut multiparty = UncheckedProposalBuilder::new();
        multiparty.add(proposal_one)?;
        multiparty.add(proposal_two)?;
        let unchecked_proposal = multiparty.build();
        assert!(unchecked_proposal?.contexts.len() == 2);
        Ok(())
    }

    #[test]
    fn finalize_multiparty() -> Result<(), BoxError> {
        use crate::psbt::PsbtExt;
        let proposal_one = v2::UncheckedProposal {
            v1: multiparty_proposal_from_test_vector(),
            context: SHARED_CONTEXT.clone(),
        };
        let proposal_two = v2::UncheckedProposal {
            v1: multiparty_proposal_from_test_vector(),
            context: SHARED_CONTEXT.clone(),
        };
        let mut finalized_multiparty = FinalizedProposal::new();
        finalized_multiparty.add(proposal_one.clone())?;
        assert_eq!(finalized_multiparty.v2()[0].type_id(), TypeId::of::<v2::UncheckedProposal>());

        finalized_multiparty.add(proposal_two)?;
        assert_eq!(finalized_multiparty.v2()[1].type_id(), TypeId::of::<v2::UncheckedProposal>());

        let multiparty_psbt =
            finalized_multiparty.combine().expect("could not create PSBT from finalized proposal");
        assert!(multiparty_psbt.validate_input_utxos().is_ok());
        Ok(())
    }
}
