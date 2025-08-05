// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::{
    group::{GroupEpoch, GroupId},
    prelude::{Capabilities, Ciphersuite, Extension, ExtensionType, UnknownExtension},
};
use tls_codec::{Deserialize as _, Serialize as _, TlsDeserialize, TlsSerialize, TlsSize};

pub(super) const HPQMLS_EXTENSION_ID: u16 = 0xFF01;
pub(super) const HPQMLS_EXTENSION_TYPE: ExtensionType = ExtensionType::Unknown(HPQMLS_EXTENSION_ID);

#[derive(Default, Debug, Clone, TlsSize, TlsSerialize, TlsDeserialize)]
#[repr(u8)]
pub enum PqtMode {
    #[default]
    ConfOnly,
    ConfAndAuth,
}

impl From<PqtMode> for bool {
    fn from(value: PqtMode) -> Self {
        match value {
            PqtMode::ConfOnly => false,
            PqtMode::ConfAndAuth => true,
        }
    }
}

#[derive(Debug, Clone, TlsSize, TlsSerialize, TlsDeserialize)]
pub(super) struct HpqMlsInfo {
    pub t_session_group_id: GroupId,
    pub pq_session_group_id: GroupId,
    pub mode: PqtMode,
    pub t_cipher_suite: Ciphersuite,
    pub pq_cipher_suite: Ciphersuite,
    pub t_epoch: GroupEpoch,
    pub pq_epoch: GroupEpoch,
}

impl HpqMlsInfo {
    pub(super) fn to_extension(&self) -> Extension {
        let hpq_mls_info = self.tls_serialize_detached().unwrap();
        let extension_content = UnknownExtension(hpq_mls_info);
        Extension::Unknown(HPQMLS_EXTENSION_ID, extension_content)
    }

    pub(super) fn increment_epoch(&mut self) {
        self.t_epoch = GroupEpoch::from(self.t_epoch.as_u64() + 1);
        self.pq_epoch = GroupEpoch::from(self.pq_epoch.as_u64() + 1);
    }
}

pub(super) fn ensure_extension_support(capabilities: Capabilities) -> Capabilities {
    let mut extensions = capabilities.extensions().to_vec();
    if !extensions.contains(&HPQMLS_EXTENSION_TYPE) {
        extensions.push(HPQMLS_EXTENSION_TYPE);
    }
    if !extensions.contains(&ExtensionType::RequiredCapabilities) {
        extensions.push(ExtensionType::RequiredCapabilities);
    }
    let ciphersuites: Vec<Ciphersuite> = capabilities
        .ciphersuites()
        .into_iter()
        .map(|cs| {
            // TODO: Stupid workaround
            let serialized_ciphersuite = cs.tls_serialize_detached().unwrap();
            Ciphersuite::tls_deserialize_exact(&serialized_ciphersuite).unwrap()
        })
        .collect();
    Capabilities::new(
        Some(capabilities.versions()),
        Some(&ciphersuites),
        Some(extensions.as_slice()),
        Some(capabilities.proposals()),
        Some(capabilities.credentials()),
    )
}
