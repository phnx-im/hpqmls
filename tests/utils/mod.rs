// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use hpqmls::HpqMlsGroup;
use openmls::prelude::{Ciphersuite, SignatureScheme};
use openmls_basic_credential::SignatureKeyPair;

pub mod client;

pub const T_SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::ED25519;
pub const T_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
// TODO: Try PQ scheme
pub const PQ_SIGNATURE_SCHEME: SignatureScheme = SignatureScheme::ECDSA_SECP256R1_SHA256;
// TODO: Try PQ ciphersuite
pub const PQ_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256;

pub fn assert_groups_eq(group1: &mut HpqMlsGroup, group2: &mut HpqMlsGroup) {
    let t_group_1_authenticator = group1.t_group.epoch_authenticator();
    let t_group_2_authenticator = group2.t_group.epoch_authenticator();
    assert_eq!(
        t_group_1_authenticator.as_slice(),
        t_group_2_authenticator.as_slice(),
        "t_group secrets do not match"
    );
    let pq_group_1_authenticator = group1.pq_group.epoch_authenticator();
    let pq_group_2_authenticator = group2.pq_group.epoch_authenticator();
    assert_eq!(
        pq_group_1_authenticator.as_slice(),
        pq_group_2_authenticator.as_slice(),
        "pq_group secrets do not match"
    );
}

pub fn init_logging() {
    let _ = env_logger::builder().is_test(true).try_init();
}
