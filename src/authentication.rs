// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::prelude::{
    BasicCredential, CredentialWithKey, CryptoError, SignaturePublicKey, SignatureScheme,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::storage::{self, CURRENT_VERSION};
use serde::{Deserialize, Serialize};
use tap::Pipe;
use tls_codec::{Serialize as _, TlsDeserialize, TlsSerialize, TlsSize};

use crate::HpqCiphersuite;

#[derive(Debug, Clone, PartialEq, Eq, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct HpqVerifyingKey {
    pub t_verifying_key: SignaturePublicKey,
    pub pq_verifying_key: SignaturePublicKey,
}

impl HpqVerifyingKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        // We unwrap here, because we know that public keys are not going to be
        // too long for the TLS codec to handle.
        self.tls_serialize_detached().unwrap()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HpqCredentialWithKey {
    pub t_credential: CredentialWithKey,
    pub pq_credential: CredentialWithKey,
}

impl HpqCredentialWithKey {
    pub fn new(identity: &[u8], keypair: &HpqSignatureKeyPair) -> Self {
        let t_credential = BasicCredential::new(identity.to_vec());
        let pq_credential = BasicCredential::new(identity.to_vec());

        Self {
            t_credential: CredentialWithKey {
                credential: t_credential.into(),
                signature_key: keypair.t_signer.public().into(),
            },
            pq_credential: CredentialWithKey {
                credential: pq_credential.into(),
                signature_key: keypair.pq_signer.public().into(),
            },
        }
    }
}

pub trait HpqSigner {
    fn t_signer(&self) -> &SignatureKeyPair;
    fn pq_signer(&self) -> &SignatureKeyPair;

    fn t_verifying_key(&self) -> &[u8] {
        self.t_signer().public()
    }
    fn pq_verifying_key(&self) -> &[u8] {
        self.pq_signer().public()
    }

    fn verifying_key(&self) -> HpqVerifyingKey {
        HpqVerifyingKey {
            t_verifying_key: self.t_verifying_key().into(),
            pq_verifying_key: self.pq_verifying_key().into(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HpqSignatureScheme {
    pub t_signature_scheme: SignatureScheme,
    pub pq_signature_scheme: SignatureScheme,
}

impl From<HpqCiphersuite> for HpqSignatureScheme {
    fn from(ciphersuite: HpqCiphersuite) -> Self {
        Self {
            t_signature_scheme: ciphersuite.t_ciphersuite.signature_algorithm(),
            pq_signature_scheme: ciphersuite.pq_ciphersuite.signature_algorithm(),
        }
    }
}

#[derive(Debug, Clone, TlsSize, TlsSerialize, TlsDeserialize, Serialize, Deserialize)]
pub struct HpqSignatureKeyPair {
    pub t_signer: SignatureKeyPair,
    pub pq_signer: SignatureKeyPair,
}

impl HpqSignatureKeyPair {
    pub fn new(signature_scheme: HpqSignatureScheme) -> Result<Self, CryptoError> {
        let t_signer = SignatureKeyPair::new(signature_scheme.t_signature_scheme)?;
        let pq_signer = SignatureKeyPair::new(signature_scheme.pq_signature_scheme)?;
        Self {
            t_signer,
            pq_signer,
        }
        .pipe(Ok)
    }

    pub fn id(&self) -> HpqStorageId {
        HpqStorageId {
            t_signature_scheme: self.t_signer().signature_scheme(),
            t_verifying_key: self.t_verifying_key().to_vec(),
            pq_signature_scheme: self.pq_signer().signature_scheme(),
            pq_verifying_key: self.pq_verifying_key().to_vec(),
        }
    }
}

impl HpqSigner for HpqSignatureKeyPair {
    fn t_signer(&self) -> &SignatureKeyPair {
        &self.t_signer
    }

    fn pq_signer(&self) -> &SignatureKeyPair {
        &self.pq_signer
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HpqStorageId {
    pub t_signature_scheme: SignatureScheme,
    pub t_verifying_key: Vec<u8>,
    pub pq_signature_scheme: SignatureScheme,
    pub pq_verifying_key: Vec<u8>,
}

// Implement key traits for the storage id
impl storage::Key<CURRENT_VERSION> for HpqStorageId {}
impl storage::traits::SignaturePublicKey<CURRENT_VERSION> for HpqStorageId {}

// Implement entity trait for the signature key pair
impl storage::Entity<CURRENT_VERSION> for HpqSignatureKeyPair {}
impl storage::traits::SignatureKeyPair<CURRENT_VERSION> for HpqSignatureKeyPair {}
