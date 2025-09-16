// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fmt::Debug;

use openmls::{
    group::{ProcessMessageError, StagedCommit},
    prelude::{
        Credential, LeafNodeIndex, MlsMessageBodyIn, ProcessedMessage, ProcessedMessageContent,
        Proposal, ProposalType, ProtocolMessage, Sender,
    },
    schedule::{ExternalPsk, PreSharedKeyId, Psk},
    storage::OpenMlsProvider,
};
use tap::Pipe as _;
use thiserror::Error;
use tls_codec::Serialize;

use crate::{
    HpqMlsGroup,
    extension::{HPQMLS_EXTENSION_ID, HpqMlsInfo},
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
    #[error("The message type is invalid for processing.")]
    InvalidMessageType,
    #[error("The MLS messages don't match.")]
    MismatchedMessages,
    #[error("HPQMLSInfo extension is missing or invalid in commit message.")]
    MissingHpqMlsInfo,
    #[error("HPQMLSInfo extension content is invalid.")]
    InvalidHpqMlsInfo,
}

#[derive(Eq)]
enum MessageType<F: Fn(&Credential, &Credential) -> bool> {
    Proposal(ProposalContent<F>),
    Commit(CommitContent<F>),
}

impl<F: Fn(&Credential, &Credential) -> bool> Debug for MessageType<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageType::Proposal(proposal) => f
                .debug_struct("Proposal")
                .field("proposal_type", &proposal.proposal_type)
                .field("credential", &proposal.credential)
                .field("leaf_index", &proposal.leaf_index)
                .finish(),
            MessageType::Commit(commit) => f
                .debug_struct("Commit")
                .field("adds", &commit.adds)
                .field("removes", &commit.removes)
                .field("updates", &commit.updates)
                .finish(),
        }
    }
}

impl<F: Fn(&Credential, &Credential) -> bool> MessageType<F> {
    fn new(processed_message: &ProcessedMessageContent, compare: F) -> Option<Self> {
        match processed_message {
            ProcessedMessageContent::ApplicationMessage(_) => None,
            ProcessedMessageContent::ProposalMessage(queued_proposal) => {
                let proposal = queued_proposal.proposal();
                let proposal_type = proposal.proposal_type();
                let (credential, leaf_index) = match proposal {
                    Proposal::Add(add_proposal) => (
                        Some(add_proposal.key_package().leaf_node().credential().clone()),
                        None,
                    ),
                    Proposal::Update(update_proposal) => {
                        (Some(update_proposal.leaf_node().credential().clone()), None)
                    }
                    Proposal::Remove(remove_proposal) => (None, Some(remove_proposal.removed())),
                    _ => (None, None),
                };
                Some(MessageType::Proposal(ProposalContent {
                    proposal_type,
                    credential,
                    leaf_index,
                    compare,
                }))
            }
            ProcessedMessageContent::ExternalJoinProposalMessage(queued_proposal) => {
                let proposal = queued_proposal.proposal();
                let proposal_type = proposal.proposal_type();
                let credential = if let Proposal::Add(add_proposal) = proposal {
                    Some(add_proposal.key_package().leaf_node().credential().clone())
                } else {
                    None
                };
                Some(MessageType::Proposal(ProposalContent {
                    proposal_type,
                    credential,
                    leaf_index: None,
                    compare,
                }))
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                let adds = staged_commit
                    .add_proposals()
                    .map(|p| {
                        p.add_proposal()
                            .key_package()
                            .leaf_node()
                            .credential()
                            .clone()
                    })
                    .collect();
                let removes = staged_commit
                    .remove_proposals()
                    .map(|p| p.remove_proposal().removed())
                    .collect();
                let updates = staged_commit
                    .update_proposals()
                    .map(|p| p.update_proposal().leaf_node().credential().clone())
                    .collect();
                let path_credential = staged_commit
                    .update_path_leaf_node()
                    .map(|node| node.credential().clone());
                Some(MessageType::Commit(CommitContent {
                    path_credential,
                    adds,
                    removes,
                    updates,
                    compare,
                }))
            }
        }
    }
}

#[derive(Debug, Eq)]
struct ProposalContent<F: Fn(&Credential, &Credential) -> bool> {
    proposal_type: ProposalType,
    credential: Option<Credential>,
    leaf_index: Option<LeafNodeIndex>,
    compare: F,
}

impl<F: Fn(&Credential, &Credential) -> bool> PartialEq for ProposalContent<F> {
    fn eq(&self, other: &Self) -> bool {
        let same_credential = match (&self.credential, &other.credential) {
            (Some(a), Some(b)) => (self.compare)(a, b),
            (None, None) => true,
            _ => false,
        };
        self.proposal_type == other.proposal_type
            && self.leaf_index == other.leaf_index
            && same_credential
    }
}

impl<F: Fn(&Credential, &Credential) -> bool> PartialEq for MessageType<F> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (MessageType::Proposal(a), MessageType::Proposal(b)) => a == b,
            (MessageType::Commit(a), MessageType::Commit(b)) => a == b,
            _ => false,
        }
    }
}

#[derive(Debug, Eq)]
struct CommitContent<F: Fn(&Credential, &Credential) -> bool> {
    path_credential: Option<Credential>,
    adds: Vec<Credential>,
    removes: Vec<LeafNodeIndex>,
    updates: Vec<Credential>,
    compare: F,
}

impl<F: Fn(&Credential, &Credential) -> bool> PartialEq for CommitContent<F> {
    fn eq(&self, other: &Self) -> bool {
        let same_path_credential = match (&self.path_credential, &other.path_credential) {
            (Some(a), Some(b)) => (self.compare)(a, b),
            (None, None) => true,
            _ => false,
        };
        same_path_credential
            && self.removes == other.removes
            && self.adds.len() == other.adds.len()
            && self.updates.len() == other.updates.len()
            && self
                .adds
                .iter()
                .zip(&other.adds)
                .all(|(a, b)| (self.compare)(a, b))
            && self
                .updates
                .iter()
                .zip(&other.updates)
                .all(|(a, b)| (self.compare)(a, b))
    }
}

#[derive(Eq)]
struct MessageInfo<F: Fn(&Credential, &Credential) -> bool> {
    msg_type: MessageType<F>,
    sender: Sender,
}

impl<F: Fn(&Credential, &Credential) -> bool> Debug for MessageInfo<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageInfo")
            .field("msg_type", &self.msg_type)
            .field("sender", &self.sender)
            .finish()
    }
}

impl<F: Fn(&Credential, &Credential) -> bool> PartialEq for MessageInfo<F> {
    fn eq(&self, other: &Self) -> bool {
        self.msg_type == other.msg_type && self.sender == other.sender
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
    pub fn process_message<F, Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        message: HpqMlsMessageIn,
        sender_equivalence: F,
    ) -> Result<HpqProcessedMessage, HpqProcessMessageError<Provider::StorageError>>
    where
        F: Fn(&Credential, &Credential) -> bool,
    {
        // We only export a PSK if we process a PQ message
        let pq_protocol_message = into_protocol_message(message.pq_message.extract())?;
        let mut pq_message = self
            .pq_group
            .process_message(provider, pq_protocol_message)?;

        let msg_type = MessageType::new(pq_message.content(), &sender_equivalence)
            .ok_or(HpqProcessMessageError::InvalidMessageType)?;
        let pq_message_info = MessageInfo {
            msg_type,
            sender: pq_message.sender().clone(),
        };

        // If we have a commit message, we need to export the PSK
        if matches!(
            pq_message.content(),
            ProcessedMessageContent::StagedCommitMessage(_)
        ) {
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
        }

        let t_protocol_message = into_protocol_message(message.t_message.extract())?;
        let t_message = self.t_group.process_message(provider, t_protocol_message)?;

        let msg_type = MessageType::new(t_message.content(), &sender_equivalence)
            .ok_or(HpqProcessMessageError::InvalidMessageType)?;
        let t_message_info = MessageInfo {
            msg_type,
            sender: t_message.sender().clone(),
        };

        // Make sure that messages match up
        if pq_message_info != t_message_info {
            return Err(HpqProcessMessageError::MismatchedMessages);
        }

        // If both are commits, the HPQMLSInfo extension must be updated and in
        // line with the info of both groups
        if let ProcessedMessageContent::StagedCommitMessage(pq_staged_commit) = pq_message.content()
            && let ProcessedMessageContent::StagedCommitMessage(t_staged_commit) =
                t_message.content()
        {
            let pq_extension =
                HpqMlsInfo::from_extensions(pq_staged_commit.group_context().extensions())
                    .map_err(|_| HpqProcessMessageError::MissingHpqMlsInfo)?
                    .ok_or(HpqProcessMessageError::MissingHpqMlsInfo)?;
            let t_extension =
                HpqMlsInfo::from_extensions(t_staged_commit.group_context().extensions())
                    .map_err(|_| HpqProcessMessageError::MissingHpqMlsInfo)?
                    .ok_or(HpqProcessMessageError::MissingHpqMlsInfo)?;

            // Extension contents must match
            let extensions_match = pq_extension == t_extension;

            // Epochs must be in line with the groups
            let epochs_match = pq_extension.pq_epoch == pq_staged_commit.group_context().epoch()
                && t_extension.t_epoch == t_staged_commit.group_context().epoch();

            // New epochs must be one higher than the current ones
            let epochs_match = pq_extension.pq_epoch.as_u64() == self.pq_group.epoch().as_u64() + 1
                && t_extension.t_epoch.as_u64() == self.t_group.epoch().as_u64() + 1;

            // Group IDs must be in line with the groups
            let group_ids_match = pq_extension.pq_session_group_id == *self.pq_group.group_id()
                && t_extension.t_session_group_id == *self.t_group.group_id();

            // Ciphersuites must be in line with the groups
            let ciphersuites_match = pq_extension.pq_cipher_suite == self.pq_group.ciphersuite()
                && t_extension.t_cipher_suite == self.t_group.ciphersuite();

            // Mode is correctly set
            let ciphersuite_matches_mode =
                self.ciphersuite() == pq_extension.mode.default_ciphersuite();

            if !extensions_match
                || !epochs_match
                || !group_ids_match
                || !ciphersuites_match
                || !ciphersuite_matches_mode
            {
                return Err(HpqProcessMessageError::InvalidHpqMlsInfo);
            }
        }

        Ok(HpqProcessedMessage {
            t_message,
            pq_message,
        })
    }
}
