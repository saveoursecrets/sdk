//! Types and traits for synchronization.

use crate::{
    commit::{CommitHash, CommitProof, CommitState},
    signer::ecdsa::Address,
    vault::VaultId,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

mod patch;

pub use patch::{AccountPatch, FolderPatch, Patch};

#[cfg(feature = "files")]
pub use patch::FilePatch;

/// Result of a checked patch on an event log.
#[derive(Debug)]
pub enum CheckedPatch {
    /// Patch was applied.
    Success(CommitProof, Vec<CommitHash>),
    /// Patch conflict.
    Conflict {
        /// Head of the event log.
        head: CommitProof,
        /// If the checked proof is contained
        /// in the event log.
        contains: Option<CommitProof>,
    },
}

/// Provides a status overview of an account.
///
/// Intended to be used during a synchronization protocol.
#[derive(Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
#[serde(default)]
pub struct SyncStatus {
    /// Indicates whether the account exists.
    pub exists: bool,
    /// Identity vault commit proof.
    pub identity: CommitProof,
    /// Account log commit proof.
    pub account: Option<CommitProof>,
    /// Commit proofs for the account folders.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub folders: HashMap<VaultId, CommitState>,
}

/// Collection of patches for an account.
#[derive(Default)]
pub struct ChangeSet {
    /// Identity vault event logs.
    pub identity: FolderPatch,
    /// Account event logs.
    pub account: AccountPatch,
    /// Folders to be imported into the new account.
    pub folders: HashMap<VaultId, FolderPatch>,
}
