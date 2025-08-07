// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use hpqmls::{
    HpqCiphersuite,
    authentication::{HpqCredentialWithKey, HpqSignatureKeyPair},
    group_builder::{DEFAULT_CIPHERSUITE, DEFAULT_PQ_CIPHERSUITE, DEFAULT_T_CIPHERSUITE},
    messages::HpqKeyPackage,
};
use openmls::{
    prelude::{BasicCredential, CredentialWithKey},
    storage::OpenMlsProvider,
};

use super::*;

pub struct Client<Provider> {
    pub signer: HpqSignatureKeyPair,
    pub credential_with_key: HpqCredentialWithKey,
    pub provider: Provider,
}

impl<Provider: OpenMlsProvider> Client<Provider> {
    pub fn new(identity: &str, provider: Provider) -> Self {
        let keypair = HpqSignatureKeyPair::new(DEFAULT_CIPHERSUITE.into());
        let credential_with_key = HpqCredentialWithKey::new(identity.as_bytes(), &keypair);

        Client {
            signer: keypair,
            credential_with_key,
            provider,
        }
    }

    pub fn generate_key_package(&self) -> HpqKeyPackage {
        HpqKeyPackage::builder()
            .build(
                &self.provider,
                DEFAULT_CIPHERSUITE,
                &self.signer,
                self.credential_with_key.clone(),
            )
            .unwrap()
            .into_key_package()
    }
}
