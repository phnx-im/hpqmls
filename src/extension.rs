// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::{
    group::{GroupEpoch, GroupId},
    prelude::{Capabilities, Ciphersuite, Extension, ExtensionType, UnknownExtension},
};
use tap::Pipe;
use tls_codec::{Deserialize as _, Serialize as _, TlsDeserialize, TlsSerialize, TlsSize};

use crate::{HpqCiphersuite, HpqMlsGroup};

pub const HPQMLS_EXTENSION_ID: u16 = 0xFF01;
pub const HPQMLS_EXTENSION_TYPE: ExtensionType = ExtensionType::Unknown(HPQMLS_EXTENSION_ID);

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

impl PqtMode {
    pub fn default_ciphersuite(&self) -> HpqCiphersuite {
        match self {
            PqtMode::ConfOnly => HpqCiphersuite::default_pq_conf(),
            PqtMode::ConfAndAuth => HpqCiphersuite::default_pq_conf_and_auth(),
        }
    }
}

#[derive(Debug, Clone, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct HpqMlsInfo {
    pub t_session_group_id: GroupId,
    pub pq_session_group_id: GroupId,
    pub mode: PqtMode,
    pub t_cipher_suite: Ciphersuite,
    pub pq_cipher_suite: Ciphersuite,
    pub t_epoch: GroupEpoch,
    pub pq_epoch: GroupEpoch,
}

impl HpqMlsInfo {
    pub(super) fn to_extension(&self) -> Result<Extension, tls_codec::Error> {
        self.tls_serialize_detached()?
            .pipe(UnknownExtension)
            .pipe(|ue| Extension::Unknown(HPQMLS_EXTENSION_ID, ue))
            .pipe(Ok)
    }

    pub(super) fn increment_epoch(&mut self) {
        self.t_epoch = GroupEpoch::from(self.t_epoch.as_u64() + 1);
        self.pq_epoch = GroupEpoch::from(self.pq_epoch.as_u64() + 1);
    }
}

pub(super) fn ensure_extension_support(
    capabilities: Capabilities,
) -> Result<Capabilities, tls_codec::Error> {
    let mut extensions = capabilities.extensions().to_vec();
    if !extensions.contains(&HPQMLS_EXTENSION_TYPE) {
        extensions.push(HPQMLS_EXTENSION_TYPE);
    }
    if !extensions.contains(&ExtensionType::RequiredCapabilities) {
        extensions.push(ExtensionType::RequiredCapabilities);
    }
    let ciphersuites: Vec<Ciphersuite> = capabilities
        .ciphersuites()
        .iter()
        .map(|&cs| cs.try_into())
        .collect::<Result<Vec<_>, _>>()?;
    Capabilities::new(
        Some(capabilities.versions()),
        Some(&ciphersuites),
        Some(extensions.as_slice()),
        Some(capabilities.proposals()),
        Some(capabilities.credentials()),
    )
    .pipe(Ok)
}

impl HpqMlsGroup {
    pub fn hpq_info(&self) -> Option<HpqMlsInfo> {
        self.t_group
            .extensions()
            .unknown(HPQMLS_EXTENSION_ID)?
            .0
            .pipe_as_ref::<'_, [u8], _>(HpqMlsInfo::tls_deserialize_exact)
            .ok()
    }
}
