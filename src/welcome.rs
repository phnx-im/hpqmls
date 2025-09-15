// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::{
    group::{MlsGroupJoinConfig, StagedWelcome, WelcomeError as OpenMlsWelcomeError},
    storage::OpenMlsProvider,
};
use thiserror::Error;

use crate::{
    HpqMlsGroup,
    messages::{HpqRatchetTreeIn, HpqWelcome},
    psk::{HpqPskError, derive_and_store_psk},
};

/// Errors that can occur when creating a new [`HpqMlsGroup`] from a welcome
/// message.
#[derive(Debug, Error)]
pub enum WelcomeError<StorageError> {
    #[error("Failed to process welcome message: {0}")]
    Processing(#[from] OpenMlsWelcomeError<StorageError>),
    #[error(transparent)]
    Psk(#[from] HpqPskError<StorageError>),
}

/// A staged HPQ welcome.
pub struct StagedHpqWelcome {
    t_staged_welcome: StagedWelcome,
    pq_staged_welcome: StagedWelcome,
}

impl HpqMlsGroup {
    /// Creates a new [`HpqMlsGroup`] from a welcome message.
    // TODO: Split into sans-io friendly parts.
    pub fn new_from_welcome<Provider: OpenMlsProvider>(
        provider: &Provider,
        mls_group_config: &MlsGroupJoinConfig,
        welcome: HpqWelcome,
        ratchet_tree: Option<HpqRatchetTreeIn>,
    ) -> Result<Self, WelcomeError<Provider::StorageError>> {
        let (t_ratchet_tree, pq_ratchet_tree) = match ratchet_tree {
            Some(r) => (Some(r.t_ratchet_tree), Some(r.pq_ratchet_tree)),
            None => (None, None),
        };
        let pq_staged_welcome = StagedWelcome::new_from_welcome(
            provider,
            mls_group_config,
            welcome.pq_welcome,
            pq_ratchet_tree,
        )?;
        let mut pq_group = pq_staged_welcome.into_group(provider)?;

        let t_ciphersuite = welcome.t_welcome.ciphersuite();

        derive_and_store_psk::<_, false>(provider, &mut pq_group, t_ciphersuite)?;

        let t_group = StagedWelcome::new_from_welcome(
            provider,
            mls_group_config,
            welcome.t_welcome,
            t_ratchet_tree,
        )?
        .into_group(provider)?;

        Ok(Self { t_group, pq_group })
    }
}

impl StagedHpqWelcome {
    /// Creates a new [`StagedHpqWelcome`] from a welcome message.
    pub fn new_from_welcome<Provider: OpenMlsProvider>(
        provider: &Provider,
        mls_group_config: &MlsGroupJoinConfig,
        welcome: HpqWelcome,
        ratchet_tree: Option<HpqRatchetTreeIn>,
    ) -> Result<Self, WelcomeError<Provider::StorageError>> {
        let (t_ratchet_tree, pq_ratchet_tree) = match ratchet_tree {
            Some(r) => (Some(r.t_ratchet_tree), Some(r.pq_ratchet_tree)),
            None => (None, None),
        };
        let t_staged_welcome = StagedWelcome::new_from_welcome(
            provider,
            mls_group_config,
            welcome.t_welcome,
            t_ratchet_tree,
        )?;
        let pq_staged_welcome = StagedWelcome::new_from_welcome(
            provider,
            mls_group_config,
            welcome.pq_welcome,
            pq_ratchet_tree,
        )?;

        Ok(StagedHpqWelcome {
            t_staged_welcome,
            pq_staged_welcome,
        })
    }

    /// Consumes the staged welcome and creates a new [`HpqMlsGroup`].
    pub fn into_group<Provider: OpenMlsProvider>(
        self,
        provider: &Provider,
    ) -> Result<HpqMlsGroup, WelcomeError<Provider::StorageError>> {
        let t_group = self.t_staged_welcome.into_group(provider)?;
        let pq_group = self.pq_staged_welcome.into_group(provider)?;

        Ok(HpqMlsGroup { t_group, pq_group })
    }
}
