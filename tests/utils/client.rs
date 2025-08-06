// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use hpqmls::{
    group_builder::{DEFAULT_PQ_CIPHERSUITE, DEFAULT_T_CIPHERSUITE},
    messages::HpqKeyPackage,
};
use openmls::{
    prelude::{BasicCredential, CredentialWithKey},
    storage::OpenMlsProvider,
};

use super::*;

pub struct Client<Provider> {
    pub t_signer: SignatureKeyPair,
    pub pq_signer: SignatureKeyPair,
    pub t_credential_with_key: CredentialWithKey,
    pub pq_credential_with_key: CredentialWithKey,
    pub provider: Provider,
}

impl<Provider: OpenMlsProvider> Client<Provider> {
    pub fn new(identity: &str, provider: Provider) -> Self {
        let t_signer = SignatureKeyPair::new(DEFAULT_T_CIPHERSUITE.signature_algorithm()).unwrap();
        let t_credential = BasicCredential::new(identity.as_bytes().to_vec());
        let t_credential_with_key = CredentialWithKey {
            credential: t_credential.into(),
            signature_key: t_signer.public().into(),
        };
        let pq_signer =
            SignatureKeyPair::new(DEFAULT_PQ_CIPHERSUITE.signature_algorithm()).unwrap();
        let pq_credential = BasicCredential::new(identity.as_bytes().to_vec());
        let pq_credential_with_key = CredentialWithKey {
            credential: pq_credential.into(),
            signature_key: pq_signer.public().into(),
        };

        Client {
            t_signer,
            pq_signer,
            t_credential_with_key,
            pq_credential_with_key,
            provider,
        }
    }

    pub fn generate_key_package(&self) -> HpqKeyPackage {
        HpqKeyPackage::builder()
            .build(
                DEFAULT_T_CIPHERSUITE,
                DEFAULT_PQ_CIPHERSUITE,
                &self.provider,
                &self.t_signer,
                &self.pq_signer,
                self.t_credential_with_key.clone(),
                self.pq_credential_with_key.clone(),
            )
            .unwrap()
            .into_key_package()
    }
}
