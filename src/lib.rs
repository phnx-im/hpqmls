// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::{
    group::{
        GroupId, Initial, Member, MlsGroup, PendingSafeExportSecretError,
        ProcessedMessageSafeExportSecretError, SafeExportSecretError,
    },
    prelude::{Ciphersuite, CryptoError, LeafNodeIndex, OpenMlsRand},
    schedule::{ExternalPsk, PreSharedKeyId, Psk, errors::PskError},
    storage::{OpenMlsProvider, StorageProvider},
};
use openmls_traits::storage::{CURRENT_VERSION, Entity, StorageProvider as _, traits};
use serde::{Deserialize, Serialize};
use tap::Pipe as _;
use thiserror::Error;
use tls_codec::{SecretVLBytes, Serialize as _, TlsSerialize, TlsSize};

use crate::{
    authentication::HpqVerifyingKey, commit_builder::CreateCommitError,
    extension::HPQMLS_EXTENSION_ID, group_builder::GroupBuilder,
};

pub mod authentication;
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Copy)]
pub struct HpqCiphersuite {
    pub t_ciphersuite: Ciphersuite,
    pub pq_ciphersuite: Ciphersuite,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, TlsSize, TlsSerialize)]
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

    pub fn commit_builder(&mut self) -> commit_builder::CommitBuilder<'_> {
        commit_builder::CommitBuilder::new(self)
    }

    /// Creates a commit builder for the T group with a GCE proposal to bump the
    /// T group epoch of the HPQInfo extension.
    pub fn t_commit_builder<E>(
        &mut self,
    ) -> Result<openmls::group::CommitBuilder<'_, Initial>, CreateCommitError<E>> {
        let mut current_hpq_info = self
            .hpq_info()
            .ok_or_else(|| CreateCommitError::MissingHpqInfo)?;
        current_hpq_info.increment_epoch();

        let mut current_extensions = self.t_group.extensions().clone();
        current_extensions.add_or_replace(current_hpq_info.to_extension()?);

        self.t_group
            .commit_builder()
            .propose_group_context_extensions(current_extensions)
            .pipe(Ok)
    }

    pub fn t_group_mut(&mut self) -> &mut MlsGroup {
        &mut self.t_group
    }

    pub fn members(&self) -> impl Iterator<Item = (Member, Member)> {
        self.t_group.members().zip(self.pq_group.members())
    }

    pub fn group_id(&self) -> HpqGroupId {
        HpqGroupId {
            t_group_id: self.t_group.group_id().clone(),
            pq_group_id: self.pq_group.group_id().clone(),
        }
    }

    pub fn verifying_key_at(&self, index: LeafNodeIndex) -> Option<HpqVerifyingKey> {
        let t_member = self.t_group.member_at(index)?;
        let pq_member = self.pq_group.member_at(index)?;
        Some(HpqVerifyingKey {
            t_verifying_key: t_member.signature_key.into(),
            pq_verifying_key: pq_member.signature_key.into(),
        })
    }

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

    pub fn delete<Storage: StorageProvider>(
        &mut self,
        provider: &Storage,
    ) -> Result<(), Storage::Error> {
        self.t_group.delete(provider)?;
        self.pq_group.delete(provider)?;
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Secret {
    value: SecretVLBytes,
}

#[derive(Debug, Serialize, Deserialize)]
struct PskBundle {
    secret: Secret,
}

impl Entity<CURRENT_VERSION> for PskBundle {}
impl traits::PskBundle<CURRENT_VERSION> for PskBundle {}

#[derive(Debug, Error)]
pub enum HpqPskError<StorageError> {
    #[error(transparent)]
    ExportFromGroup(#[from] SafeExportSecretError<StorageError>),
    #[error(transparent)]
    ExportFromProcessed(#[from] ProcessedMessageSafeExportSecretError),
    #[error(transparent)]
    ExportFromPending(#[from] PendingSafeExportSecretError<StorageError>),
    #[error("Error deriving PSK ID: {0}")]
    DerivingPskId(#[from] CryptoError),
    #[error("OpenMLS PSK error: {0}")]
    Psk(#[from] PskError),
    #[error("Error serializing PSK ID: {0}")]
    SerializingPskId(#[from] tls_codec::Error),
}

#[derive(Debug, Clone, TlsSize, TlsSerialize)]
pub struct HpqPskId {
    group_id: GroupId,
    epoch: u64,
}

fn derive_and_store_psk<Provider: openmls::storage::OpenMlsProvider, const FROM_PENDING: bool>(
    provider: &Provider,
    group: &mut MlsGroup,
    t_ciphersuite: Ciphersuite,
    //ciphersuite: Ciphersuite,
) -> Result<PreSharedKeyId, HpqPskError<Provider::StorageError>> {
    let (psk_value, epoch) = if FROM_PENDING {
        let psk_value = group.safe_export_secret_from_pending(
            provider.crypto(),
            provider.storage(),
            HPQMLS_EXTENSION_ID,
        )?;
        let epoch = group.epoch().as_u64() + 1;
        (psk_value, epoch)
    } else {
        let psk_value =
            group.safe_export_secret(provider.crypto(), provider.storage(), HPQMLS_EXTENSION_ID)?;
        (psk_value, group.epoch().as_u64())
    };
    // Prepare the PSK for the T group.
    HpqPskId {
        group_id: group.group_id().clone(),
        epoch,
    }
    .tls_serialize_detached()?
    .pipe(ExternalPsk::new)
    .pipe(Psk::External)
    .pipe(|psk| PreSharedKeyId::new(t_ciphersuite, provider.rand(), psk))?
    .pipe(|id| store_psk(provider, id, &psk_value))
}

fn store_psk<Provider: OpenMlsProvider>(
    provider: &Provider,
    psk_id: PreSharedKeyId,
    psk: &[u8],
) -> Result<PreSharedKeyId, HpqPskError<Provider::StorageError>> {
    // Delete any existing PSK with the same ID.
    provider
        .storage()
        .delete_psk::<Psk>(psk_id.psk())
        .map_err(|_| HpqPskError::Psk(PskError::Storage))?;
    psk_id.store(provider, psk)?;
    Ok(psk_id)
}
