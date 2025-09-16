// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # HPQMLS
//!
//! This crate provides an implementation of
//! [HPQMLS](https://datatracker.ietf.org/doc/draft-ietf-mls-combiner/), a
//! mechanism that combines two MLS groups, one with a traditional ciphersuite
//! and one with a post-quantum ciphersuite. An [HPQMLS group](HpqMlsGroup)
//! provides PQ security and "full" updates, as well as updates to group
//! membership provide PQ FS and PCS. In addition, the traditional group can be
//! used independently, except for membership updates, e.g. Independent use of
//! the traditional group, for example, allows for cheaper non-PQ PCS updates.
//!
//! A HPQMLS group can be run in one of two modes: "confidentiality and
//! authentication" mode, where the post-quantum ciphersuite provides both both
//! PQ confidentiality and PQ authentication, and "confidentiality-only" mode,
//! where the post-quantum ciphersuite only provides PQ confidentiality with
//! traditional authentication.

use openmls::{
    group::{GroupId, MlsGroup},
    prelude::{Ciphersuite, LeafNodeIndex, OpenMlsRand},
    storage::StorageProvider,
};
use serde::{Deserialize, Serialize};
use tls_codec::{TlsSerialize, TlsSize};

use crate::{authentication::HpqVerifyingKey, group_builder::GroupBuilder};

pub mod authentication;
pub mod commit_builder;
mod export;
pub mod extension;
pub mod group_builder;
pub mod key_package;
mod merging;
pub mod messages;
pub mod processing;
mod psk;
pub mod welcome;

/// The combined ciphersuite of a `[HpqMlsGroup]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Copy)]
pub struct HpqCiphersuite {
    t_ciphersuite: Ciphersuite,
    pq_ciphersuite: Ciphersuite,
}

impl HpqCiphersuite {
    pub const fn default_pq_conf_and_auth() -> Self {
        Self {
            t_ciphersuite: Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
            pq_ciphersuite: Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87,
        }
    }

    pub const fn default_pq_conf() -> Self {
        Self {
            t_ciphersuite: Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
            pq_ciphersuite: Ciphersuite::MLS_192_MLKEM1024_AES256GCM_SHA384_P384,
        }
    }
}

/// The group ID of a `[HpqMlsGroup]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSize, TlsSerialize)]
pub struct HpqGroupId {
    t_group_id: GroupId,
    pq_group_id: GroupId,
}

impl HpqGroupId {
    pub fn random(rng: &impl OpenMlsRand) -> Self {
        Self {
            t_group_id: GroupId::random(rng),
            pq_group_id: GroupId::random(rng),
        }
    }
}

/// An HPQMLS group, consisting of a traditional MLS group and a post-quantum MLS
/// group. The two traditional group can be used independently, except for
/// membership updates.
#[derive(Debug)]
pub struct HpqMlsGroup {
    pq_group: MlsGroup,
    pub t_group: MlsGroup,
}

impl HpqMlsGroup {
    /// Returns a reference to the post-quantum group.
    pub fn pq_group(&self) -> &MlsGroup {
        &self.pq_group
    }

    /// Build a new HPQMLS group.
    pub fn builder() -> GroupBuilder {
        GroupBuilder::new()
    }

    /// Creates a commit builder for the HPQMLS group. This builder can be used
    /// to affect membership changes and issue full updates.
    pub fn commit_builder(&mut self) -> commit_builder::CommitBuilder<'_> {
        commit_builder::CommitBuilder::new(self)
    }

    /// Returns the group ID of the HPQMLS group.
    pub fn group_id(&self) -> HpqGroupId {
        HpqGroupId {
            t_group_id: self.t_group.group_id().clone(),
            pq_group_id: self.pq_group.group_id().clone(),
        }
    }

    /// Returns the `[HpqVerifyingKey]` of the member at the given index.
    pub fn verifying_key_at(&self, index: LeafNodeIndex) -> Option<HpqVerifyingKey> {
        let t_member = self.t_group.member_at(index)?;
        let pq_member = self.pq_group.member_at(index)?;
        Some(HpqVerifyingKey {
            t_verifying_key: t_member.signature_key.into(),
            pq_verifying_key: pq_member.signature_key.into(),
        })
    }

    /// Load an HPQMLS group from storage.
    pub fn load<Storage: StorageProvider>(
        provider: &Storage,
        group_id: &HpqGroupId,
    ) -> Result<Option<Self>, Storage::Error> {
        let t_group = MlsGroup::load(provider, &group_id.t_group_id)?;
        let pq_group = MlsGroup::load(provider, &group_id.pq_group_id)?;

        Ok(t_group
            .zip(pq_group)
            .map(|(t_group, pq_group)| Self { pq_group, t_group }))
    }

    /// Delete the HPQMLS group from storage.
    pub fn delete<Storage: StorageProvider>(
        &mut self,
        provider: &Storage,
    ) -> Result<(), Storage::Error> {
        self.t_group.delete(provider)?;
        self.pq_group.delete(provider)?;
        Ok(())
    }
}
