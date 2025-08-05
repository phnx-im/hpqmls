// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::{
    prelude::{
        KeyPackage, KeyPackageIn, MlsMessageIn, MlsMessageOut, RatchetTreeIn, Welcome,
        tls_codec::Serialize,
    },
    treesync::RatchetTree,
};
use tls_codec::Deserialize;

pub struct HpqMlsMessageIn {
    pub t_message: MlsMessageIn,
    pub pq_message: Option<MlsMessageIn>,
}

/// Try to convert an HpqMlsMessageIn into a traditional MlsMessageIn.
///
/// Returns an error if the HpqMlsMessageIn contains a PQ message.
impl TryFrom<HpqMlsMessageIn> for MlsMessageIn {
    type Error = ();

    fn try_from(value: HpqMlsMessageIn) -> Result<Self, Self::Error> {
        if value.pq_message.is_some() {
            Err(())
        } else {
            Ok(value.t_message)
        }
    }
}

/// Turn a traditional MlsMessageIn into an HpqMlsMessageIn
impl From<MlsMessageIn> for HpqMlsMessageIn {
    fn from(t_message: MlsMessageIn) -> Self {
        HpqMlsMessageIn {
            t_message,
            pq_message: None,
        }
    }
}

pub struct HpqMlsMessageOut {
    pub t_message: MlsMessageOut,
    pub pq_message: Option<MlsMessageOut>,
}

impl TryFrom<HpqMlsMessageOut> for HpqMlsMessageIn {
    type Error = tls_codec::Error;

    fn try_from(value: HpqMlsMessageOut) -> Result<Self, Self::Error> {
        let serialied_t_message = value.t_message.tls_serialize_detached()?;
        let serialized_pq_message = value
            .pq_message
            .map(|msg| msg.tls_serialize_detached())
            .transpose()?;
        let t_message_in = MlsMessageIn::tls_deserialize_exact(&serialied_t_message)?;
        let pq_message_in = serialized_pq_message
            .map(MlsMessageIn::tls_deserialize_exact)
            .transpose()?;
        Ok(HpqMlsMessageIn {
            t_message: t_message_in,
            pq_message: pq_message_in,
        })
    }
}

pub struct HpqWelcome {
    pub t_welcome: Welcome,
    pub pq_welcome: Welcome,
}

pub struct HpqRatchetTree {
    pub t_ratchet_tree: RatchetTree,
    pub pq_ratchet_tree: RatchetTree,
}

impl From<HpqRatchetTree> for HpqRatchetTreeIn {
    fn from(value: HpqRatchetTree) -> Self {
        HpqRatchetTreeIn {
            t_ratchet_tree: value.t_ratchet_tree.into(),
            pq_ratchet_tree: value.pq_ratchet_tree.into(),
        }
    }
}

pub struct HpqRatchetTreeIn {
    pub t_ratchet_tree: RatchetTreeIn,
    pub pq_ratchet_tree: RatchetTreeIn,
}

#[derive(Debug, Clone)]
pub struct HpqKeyPackage {
    pub t_key_package: KeyPackage,
    pub pq_key_package: KeyPackage,
}

pub struct HpqKeyPackageIn {
    pub t_key_package: KeyPackageIn,
    pub pq_key_package: KeyPackageIn,
}
