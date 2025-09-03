// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::{
    group::{MergeCommitError, MergePendingCommitError},
    storage::{OpenMlsProvider, StorageProvider},
};

use crate::{HpqMlsGroup, processing::HpqStagedCommit};

impl HpqMlsGroup {
    /// Merges the pending [`openmls::group::StagedCommit`] of the traditional group, as well as
    /// that of the PQ group if there is one.
    pub fn merge_pending_commit<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
    ) -> Result<(), MergePendingCommitError<Provider::StorageError>> {
        self.t_group.merge_pending_commit(provider)?;
        self.pq_group.merge_pending_commit(provider)?;
        Ok(())
    }

    /// Merge a [`openmls::group::StagedCommit`] into the group after inspection. As this advances
    /// the epoch of the group, it also clears any pending commits.
    pub fn merge_staged_commit<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        staged_commit: HpqStagedCommit,
    ) -> Result<(), MergeCommitError<Provider::StorageError>> {
        let HpqStagedCommit {
            t_staged_commit,
            pq_staged_commit,
        } = staged_commit;
        self.t_group
            .merge_staged_commit(provider, t_staged_commit)?;
        if let Some(pq_staged_commit) = pq_staged_commit {
            self.pq_group
                .merge_staged_commit(provider, pq_staged_commit)?;
        }
        Ok(())
    }

    pub fn clear_pending_commits<Storage: StorageProvider>(
        &mut self,
        provider: &Storage,
    ) -> Result<(), Storage::Error> {
        self.t_group.clear_pending_commit(provider)?;
        self.pq_group.clear_pending_commit(provider)?;
        Ok(())
    }
}
