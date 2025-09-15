// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use openmls::{
    group::{ProcessMessageError, StagedCommit},
    prelude::{MlsMessageBodyIn, ProcessedMessage, ProcessedMessageContent, ProtocolMessage},
    schedule::{ExternalPsk, PreSharedKeyId, Psk},
    storage::OpenMlsProvider,
};
use tap::Pipe as _;
use thiserror::Error;
use tls_codec::Serialize;

use crate::{
    HpqMlsGroup,
    extension::HPQMLS_EXTENSION_ID,
    messages::HpqMlsMessageIn,
    psk::{HpqPskError, HpqPskId, store_psk},
};

/// A bundle consisting of the processed messages of both the traditional and
/// the PQ group.
pub struct HpqProcessedMessage {
    t_message: ProcessedMessage,
    pq_message: ProcessedMessage,
}

/// A bundle consisting of the staged commits of both the traditional and the
/// PQ group.
pub struct HpqStagedCommit {
    pub t_staged_commit: StagedCommit,
    pub pq_staged_commit: StagedCommit,
}

impl HpqProcessedMessage {
    pub fn into_staged_commit(self) -> Option<HpqStagedCommit> {
        let t_staged_commit = match self.t_message.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => *staged_commit,
            _ => return None,
        };
        let pq_staged_commit = match self.pq_message.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => *staged_commit,
            _ => return None,
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

/// Errors that can occur when processing a message with an [`HpqMlsGroup`].
#[derive(Debug, Error)]
pub enum HpqProcessMessageError<StorageError> {
    #[error("Failed to process message: {0}")]
    Processing(#[from] ProcessMessageError),
    #[error(transparent)]
    Psk(#[from] HpqPskError<StorageError>),
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
    ) -> Result<HpqProcessedMessage, HpqProcessMessageError<Provider::StorageError>> {
        // We only export a PSK if we process a PQ message
        let pq_protocol_message = into_protocol_message(message.pq_message.extract())?;
        let mut pq_message = self
            .pq_group
            .process_message(provider, pq_protocol_message)?;
        let psk_value = pq_message
            .safe_export_secret(provider.crypto(), HPQMLS_EXTENSION_ID)
            .map_err(HpqPskError::ExportFromProcessed)?;

        let next_epoch = self.pq_group.epoch().as_u64() + 1;
        HpqPskId {
            group_id: self.pq_group.group_id().clone(),
            epoch: next_epoch,
        }
        .tls_serialize_detached()
        .map_err(HpqPskError::SerializingPskId)?
        .pipe(ExternalPsk::new)
        .pipe(Psk::External)
        .pipe(|psk| PreSharedKeyId::new(self.t_group.ciphersuite(), provider.rand(), psk))
        .map_err(HpqPskError::DerivingPskId)?
        .pipe(|id| store_psk(provider, id, &psk_value))?;

        let t_protocol_message = into_protocol_message(message.t_message.extract())?;
        let t_message = self.t_group.process_message(provider, t_protocol_message)?;

        Ok(HpqProcessedMessage {
            t_message,
            pq_message,
        })
    }
}
