// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::prelude::{BasicCredential, CredentialWithKey, SignaturePublicKey, SignatureScheme};
use openmls_basic_credential::SignatureKeyPair;
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use crate::{HpqCiphersuite, group_builder::DEFAULT_CIPHERSUITE};

#[derive(Debug, Clone, PartialEq, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct HpqVerifyingKey {
    pub t_verifying_key: SignaturePublicKey,
    pub pq_verifying_key: SignaturePublicKey,
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

pub struct HpqSignatureScheme {
    pub t_signature_scheme: SignatureScheme,
    pub pq_signature_scheme: SignatureScheme,
}

impl Default for HpqSignatureScheme {
    fn default() -> Self {
        DEFAULT_CIPHERSUITE.into()
    }
}

impl From<HpqCiphersuite> for HpqSignatureScheme {
    fn from(ciphersuite: HpqCiphersuite) -> Self {
        Self {
            t_signature_scheme: ciphersuite.t_ciphersuite.signature_algorithm(),
            pq_signature_scheme: ciphersuite.pq_ciphersuite.signature_algorithm(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HpqSignatureKeyPair {
    pub t_signer: SignatureKeyPair,
    pub pq_signer: SignatureKeyPair,
}

impl HpqSignatureKeyPair {
    pub fn new(signature_scheme: HpqSignatureScheme) -> Self {
        let t_signer = SignatureKeyPair::new(signature_scheme.t_signature_scheme).unwrap();
        let pq_signer = SignatureKeyPair::new(signature_scheme.pq_signature_scheme).unwrap();
        Self {
            t_signer,
            pq_signer,
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
