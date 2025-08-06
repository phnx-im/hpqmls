// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::{
    group::{
        CommitBuilder as MlsGroupCommitBuilder, CommitMessageBundle, CreateCommitError, Initial,
        QueuedProposal,
    },
    prelude::{LeafNodeIndex, LeafNodeParameters, PreSharedKeyProposal, Proposal, ProposalType},
    storage::OpenMlsProvider,
};
use openmls_traits::signatures::Signer;
use tap::Pipe as _;
use tls_codec::Deserialize;

use crate::{
    HpqMlsGroup, derive_and_store_psk,
    extension::{HPQMLS_EXTENSION_ID, HpqMlsInfo},
    external_commit::HpqGroupInfo,
    messages::{HpqKeyPackage, HpqMlsMessageOut, HpqWelcome},
};

pub struct HpqCommitMessageBundle {
    pub commit: HpqMlsMessageOut,
    pub welcome: Option<HpqWelcome>,
    pub group_info: Option<HpqGroupInfo>,
}

impl HpqCommitMessageBundle {
    fn from_bundles(t_bundle: CommitMessageBundle, pq_bundle: Option<CommitMessageBundle>) -> Self {
        let (t_commit, t_welcome, t_group_info) = t_bundle.into_contents();
        let (pq_commit, pq_welcome, pq_group_info) = match pq_bundle {
            Some(bundle) => {
                let (commit, welcome, group_info) = bundle.into_contents();
                (Some(commit), welcome, group_info)
            }
            None => (None, None, None),
        };
        let commit = HpqMlsMessageOut {
            t_message: t_commit,
            pq_message: pq_commit,
        };
        let welcome = match (t_welcome, pq_welcome) {
            (Some(t_welcome), Some(pq_welcome)) => Some(HpqWelcome {
                t_welcome,
                pq_welcome,
            }),
            (None, None) => None,
            _ => {
                debug_assert!(false, "Inconsistent welcome messages");
                None
            }
        };
        let group_info = t_group_info.map(|t_group_info| HpqGroupInfo {
            t_group_info: t_group_info.into(),
            pq_group_info: pq_group_info.map(|pq_group_info| pq_group_info.into()),
        });
        Self {
            commit,
            welcome,
            group_info,
        }
    }

    pub fn into_message_out(self) -> HpqMlsMessageOut {
        self.commit
    }

    pub fn into_welcome(self) -> Option<HpqWelcome> {
        self.welcome
    }
}

#[derive(Debug, Clone, Default)]
struct ConfigValues {
    consume_proposal_store: Option<bool>,
    create_group_info: Option<bool>,
    force_self_update: Option<bool>,
    t_proposals: Vec<Proposal>,
    t_leaf_node_parameters: Option<LeafNodeParameters>,
    pq_leaf_node_parameters: Option<LeafNodeParameters>,
    proposed_adds: Vec<HpqKeyPackage>,
    proposed_removals: Vec<LeafNodeIndex>,
}

impl ConfigValues {
    fn apply<'b, const IS_TRADITIONAL: bool>(
        &self,
        mut builder: MlsGroupCommitBuilder<'b, Initial>,
    ) -> MlsGroupCommitBuilder<'b, Initial> {
        if let Some(consume) = self.consume_proposal_store {
            builder = builder.consume_proposal_store(consume);
        }
        if let Some(create) = self.create_group_info {
            builder = builder.create_group_info(create);
        }
        if let Some(force) = self.force_self_update {
            builder = builder.force_self_update(force);
        }
        if let Some(t_leaf_node_parameters) = &self.t_leaf_node_parameters {
            builder = builder.leaf_node_parameters(t_leaf_node_parameters.clone());
        }
        if let Some(pq_leaf_node_parameters) = &self.pq_leaf_node_parameters {
            builder = builder.leaf_node_parameters(pq_leaf_node_parameters.clone());
        }
        let (t_kps, pq_kps): (Vec<_>, Vec<_>) = self
            .proposed_adds
            .iter()
            .map(|kp| (kp.t_key_package.clone(), kp.pq_key_package.clone()))
            .unzip();
        if IS_TRADITIONAL {
            builder = builder.add_proposals(self.t_proposals.clone());
            builder = builder.propose_adds(t_kps);
        } else {
            builder = builder.propose_adds(pq_kps);
        }
        builder = builder.propose_removals(self.proposed_removals.clone());

        builder
    }
}

pub struct CommitBuilder<'a> {
    group: &'a mut HpqMlsGroup,
    values: ConfigValues,
}

impl<'a> CommitBuilder<'a> {
    /// returns a new [`CommitBuilder`] for the given [`MlsGroup`].
    pub fn new(group: &'a mut HpqMlsGroup) -> Self {
        Self {
            group,
            values: ConfigValues::default(),
        }
    }

    /// Sets whether or not the proposals in the proposal store of the group should be included in
    /// the commit. Defaults to `true`.
    pub fn consume_proposal_store(mut self, consume_proposal_store: bool) -> Self {
        self.values.consume_proposal_store = Some(consume_proposal_store);
        self
    }

    /// Sets whether or not a [`GroupInfo`] should be created when the commit is staged. Defaults to
    /// the value of the [`MlsGroup`]s [`MlsGroupJoinConfig`].
    pub fn create_group_info(mut self, create_group_info: bool) -> Self {
        self.values.create_group_info = Some(create_group_info);
        self
    }

    /// Sets whether or not the commit should force a self-update. Defaults to `false`.
    pub fn force_self_update(mut self, force_self_update: bool) -> Self {
        self.values.force_self_update = Some(force_self_update);
        self
    }

    /// Adds a proposal to the proposals to be committed in the traditional
    /// group. This must not be used with add or remove proposals.
    ///
    /// If this is used with add or remove proposals, the
    /// builder will return unchanged.
    pub fn add_t_proposal(mut self, t_proposal: Proposal) -> Self {
        if t_proposal.proposal_type() == ProposalType::Add
            || t_proposal.proposal_type() == ProposalType::Remove
        {
            return self;
        }
        self.values.t_proposals.push(t_proposal);
        self
    }

    /// Adds the proposals in the iterator to the proposals to be committed.
    /// None of the proposals may be of type Add or Remove.
    ///
    /// Any add or remove proposals are filtered out.
    pub fn add_t_proposals(mut self, t_proposals: impl IntoIterator<Item = Proposal>) -> Self {
        let iter = t_proposals.into_iter().filter(|p| {
            p.proposal_type() != ProposalType::Add && p.proposal_type() != ProposalType::Remove
        });
        self.values.t_proposals.extend(iter);
        self
    }

    /// Sets the leaf node parameters for the new leaf node in a self-update. Implies that a
    /// self-update takes place.
    pub fn leaf_node_parameters(
        mut self,
        t_leaf_node_parameters: LeafNodeParameters,
        pq_leaf_node_parameters: LeafNodeParameters,
    ) -> Self {
        self.values.t_leaf_node_parameters = Some(t_leaf_node_parameters);
        self.values.pq_leaf_node_parameters = Some(pq_leaf_node_parameters);
        self
    }

    /// Adds an Add proposal for each of the provided [`KeyPackage`] tuples to
    /// the list of proposals to be committed. The first KeyPackage in each
    /// tuple must be the traditional one and the second the post-quantum one.
    pub fn propose_adds(mut self, key_packages: impl IntoIterator<Item = HpqKeyPackage>) -> Self {
        //let (t_key_packages, pq_key_packages): (Vec<_>, Vec<_>) = key_packages
        //    .into_iter()
        //    .map(|kp| (kp.t_key_package, kp.pq_key_package))
        //    .unzip();
        self.values.proposed_adds.extend(key_packages);
        self
    }

    /// Adds a Remove proposal for the provided [`LeafNodeIndex`]es to the list of proposals to be
    /// committed.
    pub fn propose_removals(mut self, removed: impl IntoIterator<Item = LeafNodeIndex>) -> Self {
        let removed = removed.into_iter().collect::<Vec<_>>();
        self.values.proposed_removals.extend(removed);
        self
    }

    /// Perform all steps to finish the builder.
    /// - load the PSKs for the PskProposals marked for inclusion
    /// - build the commit
    /// - stage the commit
    /// TODO: Split this up to enable sans-io usage.
    pub fn finalize<S: Signer, Provider: OpenMlsProvider>(
        self,
        provider: &Provider,
        t_signer: &S,
        pq_signer: &S,
        t_f: impl FnMut(&QueuedProposal) -> bool,
        pq_f: impl FnMut(&QueuedProposal) -> bool,
    ) -> Result<HpqCommitMessageBundle, CreateCommitError> {
        let mut current_extensions = self.group.t_group.extensions().clone();
        let extension_bytes = current_extensions
            .unknown(HPQMLS_EXTENSION_ID)
            .unwrap()
            .clone()
            .0;
        let mut current_extension = HpqMlsInfo::tls_deserialize_exact(&extension_bytes)
            .expect("Failed to deserialize HpqMlsInfo extension");
        current_extension.increment_epoch();
        current_extensions.add_or_replace(current_extension.to_extension());

        // Create the PQ commit first s.t. we can export the PSK for the T group.
        let mut pq_builder = self.group.pq_group.commit_builder();
        pq_builder = self.values.apply::<false>(pq_builder);
        let pq_result = pq_builder
            .propose_group_context_extensions(current_extensions.clone())
            .load_psks(provider.storage())?
            .build(provider.rand(), provider.crypto(), pq_signer, pq_f)?
            .stage_commit(provider)
            .unwrap();
        // Prepare the PSK for the T group.
        let psk_id = derive_and_store_psk::<_, true>(
            provider,
            &mut self.group.pq_group,
            self.group.t_group.ciphersuite(),
        );
        let psk_proposal = psk_id
            .pipe(PreSharedKeyProposal::new)
            .pipe(Proposal::PreSharedKey);
        let mut t_builder = self.group.t_group.commit_builder();
        t_builder = self.values.apply::<true>(t_builder);
        let t_result = t_builder
            .add_proposal(psk_proposal)
            .propose_group_context_extensions(current_extensions)
            .load_psks(provider.storage())?
            .build(provider.rand(), provider.crypto(), t_signer, t_f)?
            .stage_commit(provider)
            .unwrap();
        Ok(HpqCommitMessageBundle::from_bundles(
            t_result,
            Some(pq_result),
        ))
    }
}
