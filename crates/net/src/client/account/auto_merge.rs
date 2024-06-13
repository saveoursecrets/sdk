//! Implements auto merge logic for a remote.

use crate::{
    client::{RemoteBridge, Result, SyncClient},
    CommitScanRequest,
};
use async_recursion::async_recursion;
use sos_sdk::{
    commit::{CommitHash, CommitProof},
    events::{EventLogExt, EventLogType},
    storage::StorageEventLogs,
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

        Ok(())
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
            let req = CommitScanRequest {
                log_type: EventLogType::Folder(*folder_id),
                offset: None,
                limit: 32,
                ascending: false,
            };
            self.scan_proofs(local, req).await?;
        }
        Ok(())
    }

    /// Scan the remote for proofs that match this client.
    #[async_recursion]
    async fn scan_proofs(
        &self,
        local: &SyncPacket,
        request: CommitScanRequest,
    ) -> Result<Option<CommitProof>> {
        let response = self.client.scan(&request).await?;
        if !response.proofs.is_empty() {
            println!("Got some proofs to compare {}", response.proofs.len(),);

            for proof in response.proofs.iter().rev() {
                let commit_hash =
                    self.compare_proof(&request.log_type, proof).await?;
                println!("Got commit hash: {:#?}", commit_hash);
            }
        }
        todo!();
    }

    /// Determine if a local event log contains a proof
    /// received from the server.
    async fn compare_proof(
        &self,
        log_type: &EventLogType,
        proof: &CommitProof,
    ) -> Result<()> {
        let account = self.account.lock().await;

        let response = match &log_type {
            EventLogType::Noop => {}
            EventLogType::Identity => {
                let log = account.identity_log().await?;
                let event_log = log.read().await;
            }
            EventLogType::Account => {
                // let reader = account.read().await;
                let log = account.account_log().await?;
                let event_log = log.read().await;
            }
            #[cfg(feature = "device")]
            EventLogType::Device => {
                // let reader = account.read().await;
                let log = account.device_log().await?;
                let event_log = log.read().await;
            }
            #[cfg(feature = "files")]
            EventLogType::Files => {
                // let reader = account.read().await;
                let log = account.file_log().await?;
                let event_log = log.read().await;
            }
            EventLogType::Folder(id) => {
                // let reader = account.read().await;
                let log = account.folder_log(id).await?;
                let event_log = log.read().await;
                let comparison = event_log.tree().compare(proof)?;
                println!("comparison: {:#?}", comparison);
            }
        };

        // todo!();

        Ok(())
    }
}
