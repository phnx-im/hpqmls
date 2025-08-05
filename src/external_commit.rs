// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::prelude::{MlsMessageIn, MlsMessageOut};
pub struct HpqGroupInfo {
    pub t_group_info: MlsMessageOut,
    pub pq_group_info: Option<MlsMessageOut>,
}

pub struct VerifiableHpqGroupInfo {
    pub t_group_info: MlsMessageIn,
    pub pq_group_info: Option<MlsMessageIn>,
}
