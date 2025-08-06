// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::{
    group::{GroupEpoch, GroupId, MlsGroupBuilder, NewGroupError, WireFormatPolicy},
    prelude::{
        Capabilities, Ciphersuite, CredentialWithKey, Extension, ExtensionType, Extensions,
        InvalidExtensionError, Lifetime, RequiredCapabilitiesExtension, SenderRatchetConfiguration,
    },
    storage::OpenMlsProvider,
    treesync::errors::LeafNodeValidationError,
};
use openmls_traits::signatures::Signer;

use crate::{
    HpqMlsGroup,
    extension::{HPQMLS_EXTENSION_TYPE, HpqMlsInfo, PqtMode, ensure_extension_support},
    key_package::ensure_ciphersuite_support,
};

pub const DEFAULT_T_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384;
pub const DEFAULT_PQ_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87;

#[derive(Debug)]
pub struct GroupBuilder {
    t_group_builder: MlsGroupBuilder,
    pq_group_builder: MlsGroupBuilder,
    // We keep track of the values below so we can do some post-processing
    // later.
    group_ids: Option<(GroupId, GroupId)>,
    mode: PqtMode,
    t_ciphersuite: Ciphersuite,
    pq_ciphersuite: Ciphersuite,
    capabilities: Capabilities,
    t_extensions: Extensions,
    pq_extensions: Extensions,
}

impl Default for GroupBuilder {
    fn default() -> Self {
        Self {
            t_group_builder: Default::default(),
            pq_group_builder: Default::default(),
            group_ids: Default::default(),
            mode: Default::default(),
            t_ciphersuite: DEFAULT_T_CIPHERSUITE,
            pq_ciphersuite: DEFAULT_PQ_CIPHERSUITE,
            capabilities: Default::default(),
            t_extensions: Default::default(),
            pq_extensions: Default::default(),
        }
    }
}

impl GroupBuilder {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub fn set_mode(mut self, mode: PqtMode) -> Self {
        self.mode = mode;
        self
    }

    /// Sets the group ID of the [`HpqMlsGroup`].
    pub fn with_group_ids(mut self, t_group_id: GroupId, pq_group_id: GroupId) -> Self {
        self.group_ids = Some((t_group_id.clone(), pq_group_id.clone()));
        self.t_group_builder = self.t_group_builder.with_group_id(t_group_id);
        self.pq_group_builder = self.pq_group_builder.with_group_id(pq_group_id);
        self
    }

    /// Build a new group as configured by this builder.
    pub fn build<Provider: OpenMlsProvider>(
        mut self,
        provider: &Provider,
        t_signer: &impl Signer,
        pq_signer: &impl Signer,
        t_credential_with_key: CredentialWithKey,
        pq_credential_with_key: CredentialWithKey,
    ) -> Result<HpqMlsGroup, NewGroupError<Provider::StorageError>> {
        // Add extension to capabilities.
        let capabilities = ensure_extension_support(self.capabilities);
        let capabilities =
            ensure_ciphersuite_support(capabilities, self.t_ciphersuite, self.pq_ciphersuite);
        self.t_group_builder = self.t_group_builder.with_capabilities(capabilities.clone());
        self.pq_group_builder = self.pq_group_builder.with_capabilities(capabilities);

        // Add extension to extensions
        let (t_group_id, pq_group_id) = self.group_ids.unwrap_or_else(|| {
            (
                GroupId::random(provider.rand()),
                GroupId::random(provider.rand()),
            )
        });

        // Add required capabilities extension
        let required_capabilities = RequiredCapabilitiesExtension::new(
            &[HPQMLS_EXTENSION_TYPE, ExtensionType::RequiredCapabilities],
            &[],
            &[],
        );
        let rc_extension = Extension::RequiredCapabilities(required_capabilities);

        self.t_extensions.add_or_replace(rc_extension.clone());
        self.pq_extensions.add_or_replace(rc_extension);

        let hpq_mls_extension = HpqMlsInfo {
            t_session_group_id: t_group_id.clone(),
            pq_session_group_id: pq_group_id.clone(),
            mode: self.mode,
            t_cipher_suite: self.t_ciphersuite,
            pq_cipher_suite: self.pq_ciphersuite,
            t_epoch: GroupEpoch::from(0),
            pq_epoch: GroupEpoch::from(0),
        }
        .to_extension();

        self.t_extensions.add_or_replace(hpq_mls_extension.clone());
        self.pq_extensions.add_or_replace(hpq_mls_extension);

        self.t_group_builder = self
            .t_group_builder
            .with_group_context_extensions(self.t_extensions)?;
        self.pq_group_builder = self
            .pq_group_builder
            .with_group_context_extensions(self.pq_extensions)?;

        let t_group = self
            .t_group_builder
            .build(provider, t_signer, t_credential_with_key)?;
        let pq_group = self
            .pq_group_builder
            .build(provider, pq_signer, pq_credential_with_key)?;
        Ok(HpqMlsGroup { pq_group, t_group })
    }

    // Builder options

    /// Sets the `wire_format` property of the HpqMlsGroup.
    pub fn with_wire_format_policy(mut self, wire_format_policy: WireFormatPolicy) -> Self {
        self.t_group_builder = self
            .t_group_builder
            .with_wire_format_policy(wire_format_policy);
        self.pq_group_builder = self
            .pq_group_builder
            .with_wire_format_policy(wire_format_policy);
        self
    }

    /// Sets the `padding_size` property of the HpqMlsGroup.
    pub fn padding_size(mut self, padding_size: usize) -> Self {
        self.t_group_builder = self.t_group_builder.padding_size(padding_size);
        self.pq_group_builder = self.pq_group_builder.padding_size(padding_size);
        self
    }

    /// Sets the `max_past_epochs` property of the traditional MlsGroup.
    /// This allows application messages from previous epochs to be decrypted.
    ///
    /// **WARNING**
    ///
    /// This feature enables the storage of message secrets from past epochs.
    /// It is a trade-off between functionality and forward secrecy and should only be enabled
    /// if the Delivery Service cannot guarantee that application messages will be sent in
    /// the same epoch in which they were generated. The number for `max_epochs` should be
    /// as low as possible.
    pub fn max_past_epochs(mut self, max_past_epochs: usize) -> Self {
        self.t_group_builder = self.t_group_builder.max_past_epochs(max_past_epochs);
        // pq group is not used for application messages, so we don't set it there
        self
    }

    /// Sets the `number_of_resumption_psks` property of the HpqMlsGroup.
    pub fn number_of_resumption_psks(mut self, number_of_resumption_psks: usize) -> Self {
        self.t_group_builder = self
            .t_group_builder
            .number_of_resumption_psks(number_of_resumption_psks);
        self.pq_group_builder = self
            .pq_group_builder
            .number_of_resumption_psks(number_of_resumption_psks);
        self
    }

    /// Sets the `use_ratchet_tree_extension` property of the MlsGroup.
    pub fn use_ratchet_tree_extension(mut self, use_ratchet_tree_extension: bool) -> Self {
        self.t_group_builder = self
            .t_group_builder
            .use_ratchet_tree_extension(use_ratchet_tree_extension);
        self.pq_group_builder = self
            .pq_group_builder
            .use_ratchet_tree_extension(use_ratchet_tree_extension);
        self
    }

    /// Sets the `sender_ratchet_configuration` property of the traditional
    /// MlsGroup. See [`SenderRatchetConfiguration`] for more information.
    pub fn sender_ratchet_configuration(
        mut self,
        sender_ratchet_configuration: SenderRatchetConfiguration,
    ) -> Self {
        self.t_group_builder = self
            .t_group_builder
            .sender_ratchet_configuration(sender_ratchet_configuration);
        // pq group does not use application messages, so we don't set the
        // configuration there
        self
    }

    /// Sets the `lifetime` of the group creator's leaf.
    pub fn lifetime(mut self, lifetime: Lifetime) -> Self {
        self.t_group_builder = self.t_group_builder.lifetime(lifetime);
        self.pq_group_builder = self.pq_group_builder.lifetime(lifetime);
        self
    }

    /// Sets the `ciphersuite` of the MlsGroup.
    pub fn ciphersuite(mut self, t_ciphersuite: Ciphersuite, pq_ciphersuite: Ciphersuite) -> Self {
        self.t_group_builder = self.t_group_builder.ciphersuite(t_ciphersuite);
        self.pq_group_builder = self.pq_group_builder.ciphersuite(pq_ciphersuite);
        self
    }

    /// Sets the initial group context extensions
    pub fn with_group_context_extensions(
        mut self,
        t_extensions: Extensions,
        pq_extensions: Extensions,
    ) -> Result<Self, InvalidExtensionError> {
        self.t_extensions = t_extensions;
        self.pq_extensions = pq_extensions;
        // We set the extensions for both groups in `build`.
        Ok(self)
    }

    /// Sets the initial leaf node extensions
    pub fn with_leaf_node_extensions(
        mut self,
        t_extensions: Extensions,
        pq_extensions: Extensions,
    ) -> Result<Self, LeafNodeValidationError> {
        self.t_group_builder = self
            .t_group_builder
            .with_leaf_node_extensions(t_extensions)?;
        self.pq_group_builder = self
            .pq_group_builder
            .with_leaf_node_extensions(pq_extensions)?;
        Ok(self)
    }

    /// Sets the group creator's [`Capabilities`]
    pub fn with_capabilities(mut self, capabilities: Capabilities) -> Self {
        self.capabilities = capabilities.clone();
        // We set the capabilities for both groups in `build`.
        self
    }
}
