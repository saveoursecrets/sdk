//! Synchronization primitives.

use crate::{
    commit::{CommitHash, CommitProof, CommitState},
    vault::{Summary, VaultId},
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;

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

/// Client can communicate with a remote server.
#[async_trait]
pub trait Client {
    /// Errors produced by the client.
    type Error;

    /// URL of the remote server.
    fn url(&self) -> &Url;

    /// Create a new account.
    async fn create_account(
        &self,
        account: &ChangeSet,
    ) -> std::result::Result<(), Self::Error>;

    /// Sync status on remote, the result is `None` when the
    /// account does not exist.
    async fn sync_status(
        &self,
    ) -> std::result::Result<Option<SyncStatus>, Self::Error>;

    /// Patch identity events.
    async fn patch_identity(
        &self,
        proof: &CommitProof,
        patch: &FolderPatch,
    ) -> std::result::Result<(), Self::Error>;

    /// List folders on the remote.
    async fn list_folders(
        &self,
    ) -> std::result::Result<Vec<Summary>, Self::Error>;

    /// Create a folder on the remote.
    async fn create_folder(
        &self,
        buffer: &[u8],
    ) -> std::result::Result<CommitProof, Self::Error>;

    /// Update an existing folder.
    ///
    /// This should be used when the commit tree has been
    /// rewritten, for example if the history was compacted
    /// or the password for a folder was changed.
    async fn update_folder(
        &self,
        id: &VaultId,
        buffer: impl AsRef<[u8]> + Send,
    ) -> std::result::Result<CommitProof, Self::Error>;

    /// Delete a folder on remote.
    async fn delete_folder(
        &self,
        id: &VaultId,
    ) -> std::result::Result<CommitProof, Self::Error>;

    /// Diff of events for a folder on remote.
    ///
    /// Returns the number of events in the patch and
    /// a buffer that can be decoded to a `FolderPatch`.
    async fn diff_folder(
        &self,
        folder_id: &VaultId,
        last_commit: &CommitHash,
        proof: &CommitProof,
    ) -> std::result::Result<(usize, Vec<u8>), Self::Error>;

    /// Load a buffer of the entire event log for a folder.
    ///
    /// The folder must already exist on the remote.
    async fn folder_events(
        &self,
        folder_id: &VaultId,
    ) -> std::result::Result<(CommitProof, Vec<u8>), Self::Error>;

    /// Commit state of a folder on a remote.
    async fn folder_status(
        &self,
        folder_id: &VaultId,
        proof: Option<&CommitProof>,
    ) -> std::result::Result<(CommitState, Option<CommitProof>), Self::Error>;

    /// Patch a folder on the remote, the folder must already exist.
    async fn patch_folder(
        &self,
        folder_id: &VaultId,
        proof: &CommitProof,
        patch: &FolderPatch,
    ) -> std::result::Result<(CommitProof, Option<CommitProof>), Self::Error>;
}
