// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::{
    prelude::{
        Capabilities, Ciphersuite, CredentialWithKey, Extensions, KeyPackageBuilder,
        KeyPackageBundle, KeyPackageNewError, Lifetime,
    },
    storage::OpenMlsProvider,
};
use openmls_traits::signatures::Signer;

use crate::{extension::ensure_extension_support, messages::HpqKeyPackage};

pub struct HpqKeyPackageBuilder {
    capabilities: Capabilities,
    t_kp_builder: KeyPackageBuilder,
    pq_kp_builder: KeyPackageBuilder,
}

pub struct HpqKeyPackageBundle {
    t_kp_bundle: KeyPackageBundle,
    pq_kp_bundle: KeyPackageBundle,
}

impl HpqKeyPackageBundle {
    pub fn into_key_package(self) -> HpqKeyPackage {
        HpqKeyPackage {
            t_key_package: self.t_kp_bundle.key_package().clone(),
            pq_key_package: self.pq_kp_bundle.key_package().clone(),
        }
    }
}

impl HpqKeyPackageBuilder {
    /// Create a key package builder.
    pub fn new() -> Self {
        Self {
            capabilities: Capabilities::default(),
            t_kp_builder: KeyPackageBuilder::new(),
            pq_kp_builder: KeyPackageBuilder::new(),
        }
    }

    /// Set the key package lifetime.
    pub fn key_package_lifetime(mut self, lifetime: Lifetime) -> Self {
        self.t_kp_builder = self.t_kp_builder.key_package_lifetime(lifetime);
        self.pq_kp_builder = self.pq_kp_builder.key_package_lifetime(lifetime);
        self
    }

    /// Set the key package extensions.
    pub fn key_package_extensions(mut self, extensions: Extensions) -> Self {
        self.t_kp_builder = self.t_kp_builder.key_package_extensions(extensions.clone());
        self.pq_kp_builder = self.pq_kp_builder.key_package_extensions(extensions);
        self
    }

    /// Mark the key package as a last-resort key package via a [`LastResortExtension`].
    pub fn mark_as_last_resort(mut self) -> Self {
        self.t_kp_builder = self.t_kp_builder.mark_as_last_resort();
        self.pq_kp_builder = self.pq_kp_builder.mark_as_last_resort();
        self
    }

    /// Set the leaf node capabilities.
    pub fn leaf_node_capabilities(mut self, capabilities: Capabilities) -> Self {
        self.capabilities = capabilities;
        // The capabilities are set in `build`, so we don't set them here.
        self
    }

    /// Set the leaf node extensions.
    pub fn leaf_node_extensions(mut self, extensions: Extensions) -> Self {
        self.t_kp_builder = self.t_kp_builder.leaf_node_extensions(extensions.clone());
        self.pq_kp_builder = self.pq_kp_builder.leaf_node_extensions(extensions);
        self
    }

    /// Finalize and build the key package.
    pub fn build(
        mut self,
        t_ciphersuite: Ciphersuite,
        pq_ciphersuite: Ciphersuite,
        provider: &impl OpenMlsProvider,
        t_signer: &impl Signer,
        pq_signer: &impl Signer,
        t_credential_with_key: CredentialWithKey,
        pq_credential_with_key: CredentialWithKey,
    ) -> Result<HpqKeyPackageBundle, KeyPackageNewError> {
        let capabilities = ensure_extension_support(self.capabilities);
        self.t_kp_builder = self
            .t_kp_builder
            .leaf_node_capabilities(capabilities.clone());
        self.pq_kp_builder = self.pq_kp_builder.leaf_node_capabilities(capabilities);
        let t_kp_bundle =
            self.t_kp_builder
                .build(t_ciphersuite, provider, t_signer, t_credential_with_key)?;
        let pq_kp_bundle = self.pq_kp_builder.build(
            pq_ciphersuite,
            provider,
            pq_signer,
            pq_credential_with_key,
        )?;
        Ok(HpqKeyPackageBundle {
            t_kp_bundle,
            pq_kp_bundle,
        })
    }
}

impl HpqKeyPackage {
    pub fn builder() -> HpqKeyPackageBuilder {
        HpqKeyPackageBuilder::new()
    }
}
