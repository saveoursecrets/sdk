//! Implements auto merge logic for a remote.

use crate::client::{RemoteBridge, Result};
use sos_sdk::{
    commit::CommitHash,
    sync::{MaybeConflict, SyncPacket},
    vault::VaultId,
};
use tracing::instrument;

impl RemoteBridge {
    /// Try to auto merge on conflict.
    ///
    /// Searches the remote event log for a common ancestor and
    /// attempts to merge commits from the common ancestor with the
    /// diff that would have been applied.
    ///
    /// Once the changes have been merged a force update of the
    /// server is necessary.
    #[instrument(skip_all)]
    pub(crate) async fn auto_merge(
        &self,
        conflict: MaybeConflict,
        local: SyncPacket,
        _remote: SyncPacket,
    ) -> Result<()> {
        if conflict.identity {
            self.auto_merge_identity(&local).await?;
        }

        if conflict.account {
            self.auto_merge_account(&local).await?;
        }

        #[cfg(feature = "device")]
        if conflict.device {
            self.auto_merge_device(&local).await?;
        }

        #[cfg(feature = "files")]
        if conflict.files {
            self.auto_merge_files(&local).await?;
        }

        for (folder_id, _) in &conflict.folders {
            self.auto_merge_folder(&local, folder_id).await?;
        }

        todo!();
    }

    async fn auto_merge_identity(&self, local: &SyncPacket) -> Result<()> {
        let conflicting_state = &local.status.identity;
        todo!();
    }

    async fn auto_merge_account(&self, local: &SyncPacket) -> Result<()> {
        let conflicting_state = &local.status.account;
        todo!();
    }

    #[cfg(feature = "device")]
    async fn auto_merge_device(&self, local: &SyncPacket) -> Result<()> {
        let conflicting_state = &local.status.device;
        todo!();
    }

    #[cfg(feature = "files")]
    async fn auto_merge_files(&self, local: &SyncPacket) -> Result<()> {
        let conflicting_state = &local.status.files;
        todo!();
    }

    async fn auto_merge_folder(
        &self,
        local: &SyncPacket,
        folder_id: &VaultId,
    ) -> Result<()> {
        if let Some(commit_state) = &local.status.folders.get(folder_id) {
            todo!();
        }
        Ok(())
    }

    /// Try to find a common ancestor commit.
    async fn find_ancestor(&self) -> Result<Option<CommitHash>> {
        todo!();
    }
}
