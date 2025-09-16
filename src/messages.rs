// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::{
    prelude::{
        Ciphersuite, KeyPackage, KeyPackageIn, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut,
        OpenMlsCrypto, OpenMlsSignaturePublicKey, ProtocolVersion, RatchetTreeIn, SignatureError,
        Verifiable as _, Welcome,
        group_info::{GroupInfo, VerifiableGroupInfo},
    },
    treesync::RatchetTree,
};
use serde::{Deserialize, Serialize};
use tls_codec::{Deserialize as _, Serialize as _, TlsDeserialize, TlsSerialize, TlsSize};

use crate::{authentication::HpqVerifyingKey, extension::PqtMode};

/// An incoming message for processing by an `[HpqMlsGroup]`.
#[derive(Debug, Clone, TlsDeserialize, TlsSize)]
pub struct HpqMlsMessageIn {
    pub(crate) t_message: MlsMessageIn,
    pub(crate) pq_message: MlsMessageIn,
}

impl HpqMlsMessageIn {
    pub fn into_welcome(self) -> Option<HpqWelcome> {
        let MlsMessageBodyIn::Welcome(t_welcome) = self.t_message.extract() else {
            return None;
        };
        let MlsMessageBodyIn::Welcome(pq_welcome) = self.pq_message.extract() else {
            return None;
        };
        Some(HpqWelcome {
            t_welcome,
            pq_welcome,
        })
    }

    pub fn into_key_package(self) -> Option<HpqKeyPackageIn> {
        let MlsMessageBodyIn::KeyPackage(t_key_package) = self.t_message.extract() else {
            return None;
        };
        let MlsMessageBodyIn::KeyPackage(pq_key_package) = self.pq_message.extract() else {
            return None;
        };
        Some(HpqKeyPackageIn {
            t_key_package,
            pq_key_package,
        })
    }
}

/// An outgoing message from an `[HpqMlsGroup]`.
#[derive(Debug, Clone, TlsSerialize, TlsSize, Serialize, Deserialize)]
pub struct HpqMlsMessageOut {
    pub(crate) t_message: MlsMessageOut,
    pub(crate) pq_message: MlsMessageOut,
}

impl TryFrom<HpqMlsMessageOut> for HpqMlsMessageIn {
    type Error = tls_codec::Error;

    fn try_from(value: HpqMlsMessageOut) -> Result<Self, Self::Error> {
        let serialied_t_message = value.t_message.tls_serialize_detached()?;
        let serialized_pq_message = value.pq_message.tls_serialize_detached()?;
        let t_message_in = MlsMessageIn::tls_deserialize_exact(&serialied_t_message)?;
        let pq_message_in = MlsMessageIn::tls_deserialize_exact(&serialized_pq_message)?;
        Ok(HpqMlsMessageIn {
            t_message: t_message_in,
            pq_message: pq_message_in,
        })
    }
}

/// A welcome message for joining an `[HpqMlsGroup]`.
pub struct HpqWelcome {
    pub(crate) t_welcome: Welcome,
    pub(crate) pq_welcome: Welcome,
}

impl From<HpqWelcome> for HpqMlsMessageOut {
    fn from(value: HpqWelcome) -> Self {
        HpqMlsMessageOut {
            t_message: MlsMessageOut::from_welcome(value.t_welcome, ProtocolVersion::default()),
            pq_message: MlsMessageOut::from_welcome(value.pq_welcome, ProtocolVersion::default()),
        }
    }
}

/// A ratchet tree for an `[HpqMlsGroup]`.
pub struct HpqRatchetTree {
    pub(crate) t_ratchet_tree: RatchetTree,
    pub(crate) pq_ratchet_tree: RatchetTree,
}

impl From<HpqRatchetTree> for HpqRatchetTreeIn {
    fn from(value: HpqRatchetTree) -> Self {
        HpqRatchetTreeIn {
            t_ratchet_tree: value.t_ratchet_tree.into(),
            pq_ratchet_tree: value.pq_ratchet_tree.into(),
        }
    }
}

/// An unverified ratchet tree for an `[HpqMlsGroup]`.
pub struct HpqRatchetTreeIn {
    pub(crate) t_ratchet_tree: RatchetTreeIn,
    pub(crate) pq_ratchet_tree: RatchetTreeIn,
}

/// A key package to add members to an `[HpqMlsGroup]`.
#[derive(Debug, Clone)]
pub struct HpqKeyPackage {
    pub(crate) t_key_package: KeyPackage,
    pub(crate) pq_key_package: KeyPackage,
}

impl HpqKeyPackage {
    pub fn mode(&self) -> PqtMode {
        match self.pq_key_package.ciphersuite() {
            Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87 => PqtMode::ConfAndAuth,
            _ => PqtMode::ConfOnly,
        }
    }
}

impl From<HpqKeyPackage> for HpqMlsMessageOut {
    fn from(value: HpqKeyPackage) -> Self {
        HpqMlsMessageOut {
            t_message: MlsMessageOut::from(value.t_key_package),
            pq_message: MlsMessageOut::from(value.pq_key_package),
        }
    }
}

/// An unverified key package for adding members to an `[HpqMlsGroup]`.
pub struct HpqKeyPackageIn {
    pub(crate) t_key_package: KeyPackageIn,
    pub(crate) pq_key_package: KeyPackageIn,
}

/// The group info of an `[HpqMlsGroup]`.
pub struct HpqGroupInfo {
    pub(crate) t_group_info: GroupInfo,
    pub(crate) pq_group_info: GroupInfo,
}

impl From<HpqGroupInfo> for HpqMlsMessageOut {
    fn from(value: HpqGroupInfo) -> Self {
        HpqMlsMessageOut {
            t_message: MlsMessageOut::from(value.t_group_info),
            pq_message: MlsMessageOut::from(value.pq_group_info),
        }
    }
}

/// A verifiable group info for an `[HpqMlsGroup]`.
pub struct VerifiableHpqGroupInfo {
    pub(crate) t_group_info: VerifiableGroupInfo,
    pub(crate) pq_group_info: VerifiableGroupInfo,
}

impl VerifiableHpqGroupInfo {
    /// Verifies the group info and returns the contained [`HpqGroupInfo`].
    pub fn verify(
        self,
        provider: &impl OpenMlsCrypto,
        verifying_key: &HpqVerifyingKey,
    ) -> Result<HpqGroupInfo, SignatureError> {
        let t_verifying_key = OpenMlsSignaturePublicKey::from_signature_key(
            verifying_key.t_verifying_key.clone(),
            self.t_group_info.ciphersuite().signature_algorithm(),
        );
        let pq_verifying_key = OpenMlsSignaturePublicKey::from_signature_key(
            verifying_key.pq_verifying_key.clone(),
            self.pq_group_info.ciphersuite().signature_algorithm(),
        );
        Ok(HpqGroupInfo {
            t_group_info: self.t_group_info.verify(provider, &t_verifying_key)?,
            pq_group_info: self.pq_group_info.verify(provider, &pq_verifying_key)?,
        })
    }
}
