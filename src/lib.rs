// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::{
    group::{GroupId, Member, MlsGroup},
    prelude::{Ciphersuite, OpenMlsRand},
    schedule::{ExternalPsk, PreSharedKeyId, Psk},
    storage::StorageProvider,
};
use sha2::{Digest, Sha256};
use tap::Pipe as _;

use crate::{extension::HPQMLS_EXTENSION_ID, group_builder::GroupBuilder};

pub mod commit_builder;
pub mod export;
pub mod extension;
pub mod external_commit;
pub mod group_builder;
pub mod key_package;
pub mod merging;
pub mod messages;
pub mod processing;
pub mod welcome;

#[derive(Debug)]
pub struct HpqGroupId {
    pub t_group_id: GroupId,
    pub pq_group_id: GroupId,
}

impl HpqGroupId {
    pub fn random(rng: &impl OpenMlsRand) -> Self {
        Self {
            t_group_id: GroupId::random(rng),
            pq_group_id: GroupId::random(rng),
        }
    }
}

pub struct HpqMlsGroup {
    pub pq_group: MlsGroup,
    pub t_group: MlsGroup,
}

impl HpqMlsGroup {
    pub fn builder() -> GroupBuilder {
        GroupBuilder::new()
    }

    pub fn commit_builder(&mut self) -> commit_builder::CommitBuilder {
        commit_builder::CommitBuilder::new(self)
    }

    pub fn t_group_mut(&mut self) -> &mut MlsGroup {
        &mut self.t_group
    }

    pub fn members(&self) -> impl Iterator<Item = (Member, Member)> {
        self.t_group.members().zip(self.pq_group.members())
    }

    pub fn load<Storage: StorageProvider>(
        provider: &Storage,
        t_group_id: &GroupId,
        pq_group_id: &GroupId,
    ) -> Result<Option<Self>, Storage::Error> {
        let t_group = MlsGroup::load(provider, t_group_id)?;
        let pq_group = MlsGroup::load(provider, pq_group_id)?;

        Ok(t_group
            .zip(pq_group)
            .map(|(t_group, pq_group)| Self { pq_group, t_group }))
    }
}

fn derive_and_store_psk<Provider: openmls::storage::OpenMlsProvider, const FROM_PENDING: bool>(
    provider: &Provider,
    group: &mut MlsGroup,
    ciphersuite: Ciphersuite,
) -> PreSharedKeyId {
    let (psk_value, epoch) = if FROM_PENDING {
        let psk_value = group
            .safe_export_secret_from_pending(
                provider.crypto(),
                provider.storage(),
                HPQMLS_EXTENSION_ID,
            )
            .unwrap();
        let epoch = group.epoch().as_u64() + 1;
        (psk_value, epoch)
    } else {
        let psk_value = group
            .safe_export_secret(provider.crypto(), provider.storage(), HPQMLS_EXTENSION_ID)
            .unwrap();
        (psk_value, group.epoch().as_u64())
    };
    let mut psk_id_payload = group.group_id().as_slice().to_vec();
    psk_id_payload.extend(epoch.to_be_bytes());
    let psk_id = Sha256::digest(psk_id_payload).to_vec();
    // Prepare the PSK for the T group.
    let psk_id = psk_id
        .clone()
        .pipe(ExternalPsk::new)
        .pipe(Psk::External)
        .pipe(|psk| PreSharedKeyId::new(ciphersuite, provider.rand(), psk))
        .unwrap();
    psk_id.store(provider, &psk_value).unwrap();
    psk_id
}
