// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::{
    group::{MlsGroupJoinConfig, StagedWelcome, WelcomeError},
    storage::OpenMlsProvider,
};

use crate::{
    HpqMlsGroup, derive_and_store_psk,
    group_builder::DEFAULT_T_CIPHERSUITE,
    messages::{HpqRatchetTreeIn, HpqWelcome},
};

pub struct StagedHpqWelcome {
    pub t_staged_welcome: StagedWelcome,
    pub pq_staged_welcome: StagedWelcome,
}

impl HpqMlsGroup {
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

        derive_and_store_psk::<_, false>(provider, &mut pq_group, DEFAULT_T_CIPHERSUITE);
        println!("Derived and stored PSK for PQ group");

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

    pub fn into_group<Provider: OpenMlsProvider>(
        self,
        provider: &Provider,
    ) -> Result<HpqMlsGroup, WelcomeError<Provider::StorageError>> {
        let t_group = self.t_staged_welcome.into_group(provider)?;
        let pq_group = self.pq_staged_welcome.into_group(provider)?;

        Ok(HpqMlsGroup { t_group, pq_group })
    }
}
