//! Synchronization primitives.

use crate::{
    commit::{CommitHash, CommitProof, CommitState, Comparison},
    events::{
        AccountEvent, AccountEventLog, EventLogExt, FolderEventLog,
        WriteEvent,
    },
    vault::VaultId,
    Error, Result,
};
use async_trait::async_trait;
use binary_stream::futures::{Decodable, Encodable};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use url::Url;

mod patch;

pub use patch::{AccountPatch, FolderPatch, Patch};

#[cfg(feature = "files")]
pub use patch::FilePatch;

/// Options for folder merge.
pub enum FolderMergeOptions<'a> {
    /// Update a URN lookup when merging.
    Urn(VaultId, &'a mut crate::identity::UrnLookup),
    /// Update a search index when merging.
    #[cfg(feature = "search")]
    Search(&'a mut crate::storage::search::SearchIndex),
}

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

/// Diff between local and remote.
#[derive(Default, Debug)]
pub struct Diff<T>
where
    T: Default + Encodable + Decodable,
{
    /// Contents of the patch.
    pub patch: Patch<T>,
    /// Head of the event log before applying the patch.
    pub before: CommitProof,
    /// Head of the event log after applying the patch.
    pub after: CommitProof,
}

/// Diff between account events logs.
pub type AccountDiff = Diff<AccountEvent>;

/// Diff between folder events logs.
pub type FolderDiff = Diff<WriteEvent>;

/// Provides a status overview of an account.
///
/// Intended to be used during a synchronization protocol.
#[derive(Debug, Default, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(default)]
pub struct SyncStatus {
    /// Identity vault commit state.
    pub identity: CommitState,
    /// Account log commit state.
    pub account: CommitState,
    /// Commit proofs for the account folders.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub folders: HashMap<VaultId, CommitState>,
}

/// Diff between all events logs on local and remote.
#[derive(Default, Debug)]
pub struct SyncDiff {
    /// Diff of the identity vault event logs.
    pub identity: Option<FolderDiff>,
    /// Diff of the account event log.
    pub account: Option<AccountDiff>,
    /// Diff for folders in the account.
    pub folders: HashMap<VaultId, FolderDiff>,
}

/// Comparison between local and remote status.
#[derive(Debug)]
pub struct SyncComparison {
    /// Local sync status.
    pub local_status: SyncStatus,
    /// Remote sync status.
    pub remote_status: SyncStatus,
    /// Comparison of the identity event log.
    pub identity: Comparison,
    /// Comparison of the account event log.
    pub account: Comparison,
    /// Comparison for each folder in the account.
    pub folders: HashMap<VaultId, Comparison>,
}

impl SyncComparison {
    /// Create a new sync comparison.
    pub async fn new(
        storage: &impl SyncStorage,
        remote_status: SyncStatus,
    ) -> Result<SyncComparison> {
        let local_status = storage.sync_status().await?;

        let identity = {
            let identity = storage.identity_log();
            let reader = identity.read().await;
            reader.tree().compare(&remote_status.identity.1)?
        };

        let account = {
            let account = storage.account_log();
            let reader = account.read().await;
            reader.tree().compare(&remote_status.account.1)?
        };

        let folders = {
            let mut folders = HashMap::new();
            for (id, folder) in &remote_status.folders {
                // Folder may exist on remote but not locally
                // if we have just deleted a folder
                if let Ok(event_log) = storage.folder_log(id) {
                    let event_log = event_log.read().await;
                    folders.insert(*id, event_log.tree().compare(&folder.1)?);
                }
            }
            folders
        };

        Ok(SyncComparison {
            local_status,
            remote_status,
            identity,
            account,
            folders,
        })
    }

    /// Determine if synchronization is required.
    pub fn needs_sync(&self) -> bool {
        self.local_status != self.remote_status
    }

    /// Build a diff from this comparison.
    pub async fn diff(&self, storage: &impl SyncStorage) -> Result<SyncDiff> {
        let mut diff: SyncDiff = Default::default();

        match self.identity {
            Comparison::Equal => {}
            Comparison::Contains(_, _) => {
                // Need to push changes to remote
                let log = storage.identity_log();
                let reader = log.read().await;
                let is_last_commit = Some(&self.remote_status.identity.0)
                    == reader.tree().last_commit().as_ref();

                // Avoid empty patches when commit is already the last
                if !is_last_commit {
                    let after = reader.tree().head()?;
                    let identity = FolderDiff {
                        patch: reader
                            .diff(Some(&self.remote_status.identity.0))
                            .await?,
                        after,
                        before: self.remote_status.identity.1.clone(),
                    };
                    diff.identity = Some(identity);
                }
            }
            Comparison::Unknown => {
                //unreachable!("identity event log is never rewritten");
            }
        }

        match self.account {
            Comparison::Equal => {}
            Comparison::Contains(_, _) => {
                // Need to push changes to remote
                let log = storage.account_log();
                let reader = log.read().await;

                let is_last_commit = Some(&self.remote_status.account.0)
                    == reader.tree().last_commit().as_ref();

                // Avoid empty patches when commit is already the last
                if !is_last_commit {
                    let after = reader.tree().head()?;
                    let account = AccountDiff {
                        patch: reader
                            .diff(Some(&self.remote_status.account.0))
                            .await?,
                        after,
                        before: self.remote_status.account.1.clone(),
                    };
                    diff.account = Some(account);
                }
            }
            Comparison::Unknown => {
                //unreachable!("account event log is never rewritten");
            }
        }

        for (id, folder) in &self.folders {
            let commit_state = self
                .remote_status
                .folders
                .get(id)
                .ok_or(Error::CacheNotAvailable(*id))?;

            match folder {
                Comparison::Equal => {}
                Comparison::Contains(_, _) => {
                    // Need to push changes to remote
                    let log = storage.folder_log(id)?;
                    let log = log.read().await;

                    let is_last_commit = Some(&commit_state.0)
                        == log.tree().last_commit().as_ref();

                    if !is_last_commit {
                        let after = log.tree().head()?;
                        let folder = FolderDiff {
                            patch: log.diff(Some(&commit_state.0)).await?,
                            after,
                            before: commit_state.1.clone(),
                        };

                        diff.folders.insert(*id, folder);
                    }
                }
                Comparison::Unknown => {
                    println!("todo! : handle folder with diverged trees");
                }
            }
        }

        Ok(diff)
    }
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

    /// Sync with a remote.
    async fn sync(
        &self,
        local_status: &SyncStatus,
        diff: &SyncDiff,
    ) -> std::result::Result<SyncDiff, Self::Error>;
}

/// Storage implementations that can synchronize.
#[async_trait]
pub trait SyncStorage {
    /// Get the sync status.
    async fn sync_status(&self) -> Result<SyncStatus>;

    /// Clone of the identity log.
    fn identity_log(&self) -> Arc<RwLock<FolderEventLog>>;

    /// Clone of the account log.
    fn account_log(&self) -> Arc<RwLock<AccountEventLog>>;

    /// Folder event log.
    fn folder_log(&self, id: &VaultId)
        -> Result<Arc<RwLock<FolderEventLog>>>;
}
