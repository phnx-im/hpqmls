// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::{
    group::{ProcessMessageError, StagedCommit},
    prelude::{MlsMessageBodyIn, ProcessedMessage, ProcessedMessageContent, ProtocolMessage},
    schedule::{ExternalPsk, PreSharedKeyId, Psk},
    storage::OpenMlsProvider,
};
use sha2::{Digest as _, Sha256};
use tap::Pipe as _;

use crate::{HpqMlsGroup, extension::HPQMLS_EXTENSION_ID, messages::HpqMlsMessageIn};

pub struct HpqProcessedMessage {
    pub t_message: ProcessedMessage,
    pub pq_message: Option<ProcessedMessage>,
}

pub struct HpqStagedCommit {
    pub t_staged_commit: StagedCommit,
    pub pq_staged_commit: Option<StagedCommit>,
}

impl HpqProcessedMessage {
    pub fn into_staged_commit(self) -> Option<HpqStagedCommit> {
        let t_staged_commit = match self.t_message.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => *staged_commit,
            _ => return None,
        };
        let pq_staged_commit = if let Some(pq_message) = self.pq_message {
            match pq_message.into_content() {
                ProcessedMessageContent::StagedCommitMessage(staged_commit) => Some(*staged_commit),
                _ => return None,
            }
        } else {
            None
        };
        Some(HpqStagedCommit {
            t_staged_commit,
            pq_staged_commit,
        })
    }
}

fn into_protocol_message(
    message: MlsMessageBodyIn,
) -> Result<ProtocolMessage, ProcessMessageError> {
    match message {
        MlsMessageBodyIn::PrivateMessage(pm) => Ok(ProtocolMessage::PrivateMessage(pm)),
        MlsMessageBodyIn::PublicMessage(pm) => Ok(ProtocolMessage::PublicMessage(pm.into())),
        _ => Err(ProcessMessageError::IncompatibleWireFormat),
    }
}

impl HpqMlsGroup {
    /// Parses incoming messages from the DS. Checks for syntactic errors and
    /// makes some semantic checks as well. If the input is an encrypted
    /// message, it will be decrypted. This processing function does syntactic
    /// and semantic validation of the message. It returns a [ProcessedMessage]
    /// enum.
    ///
    /// # Errors:
    /// Returns an [`ProcessMessageError`] when the validation checks fail
    /// with the exact reason of the failure.
    pub fn process_message<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        message: HpqMlsMessageIn,
    ) -> Result<HpqProcessedMessage, ProcessMessageError> {
        let pq_message = match message.pq_message {
            None => None,
            Some(pq_message) => {
                let pq_protocol_message = into_protocol_message(pq_message.extract())?;
                let mut pq_processed_message = self
                    .pq_group
                    .process_message(provider, pq_protocol_message)?;
                let psk_value = pq_processed_message
                    .safe_export_secret(provider.crypto(), HPQMLS_EXTENSION_ID)
                    .unwrap();
                let mut psk_id_payload = self.pq_group.group_id().as_slice().to_vec();
                let next_epoch = self.pq_group.epoch().as_u64() + 1;
                psk_id_payload.extend(next_epoch.to_be_bytes());
                let psk_id = Sha256::digest(psk_id_payload)
                    .to_vec()
                    .pipe(ExternalPsk::new)
                    .pipe(Psk::External)
                    .pipe(|psk| {
                        PreSharedKeyId::new(self.t_group.ciphersuite(), provider.rand(), psk)
                    })
                    .unwrap();
                psk_id.store(provider, &psk_value).unwrap();
                Some(pq_processed_message)
            }
        };

        let t_protocol_message = into_protocol_message(message.t_message.extract())?;
        let t_message = self.t_group.process_message(provider, t_protocol_message)?;

        Ok(HpqProcessedMessage {
            t_message,
            pq_message,
        })
    }
}
