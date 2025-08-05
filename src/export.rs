// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::{
    group::{ExportGroupInfoError, ExportSecretError, SafeExportSecretError},
    prelude::OpenMlsCrypto,
    storage::StorageProvider,
};
use openmls_traits::signatures::Signer;

use crate::{HpqMlsGroup, external_commit::HpqGroupInfo, messages::HpqRatchetTree};

impl HpqMlsGroup {
    pub fn export_ratchet_tree(&self) -> HpqRatchetTree {
        let t_ratchet_tree = self.t_group.export_ratchet_tree();
        let pq_ratchet_tree = self.pq_group.export_ratchet_tree();
        HpqRatchetTree {
            t_ratchet_tree,
            pq_ratchet_tree,
        }
    }

    pub fn export_group_info(
        &self,
        crypto: &impl OpenMlsCrypto,
        t_signer: &impl Signer,
        pq_signer: &impl Signer,
        with_ratchet_tree: bool,
    ) -> Result<HpqGroupInfo, ExportGroupInfoError> {
        let t_group_info = self
            .t_group
            .export_group_info(crypto, t_signer, with_ratchet_tree)?;
        let pq_group_info =
            self.pq_group
                .export_group_info(crypto, pq_signer, with_ratchet_tree)?;
        let group_info = HpqGroupInfo {
            t_group_info,
            pq_group_info: Some(pq_group_info),
        };
        Ok(group_info)
    }

    pub fn export_secret<CryptoProvider: OpenMlsCrypto>(
        &self,
        crypto: &CryptoProvider,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>, ExportSecretError> {
        self.t_group
            .export_secret(crypto, label, context, key_length)
    }

    pub fn safe_export_secret<Crypto: OpenMlsCrypto, Storage: StorageProvider>(
        &mut self,
        crypto: &Crypto,
        storage: &Storage,
        component_id: u16,
    ) -> Result<Vec<u8>, SafeExportSecretError<Storage::Error>> {
        self.t_group
            .safe_export_secret(crypto, storage, component_id)
    }
}
