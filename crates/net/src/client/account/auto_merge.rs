//! Implements auto merge logic for a remote.

use crate::{
    client::{RemoteBridge, Result, SyncClient},
    CommitDiffRequest, CommitScanRequest,
};
use async_recursion::async_recursion;
use binary_stream::futures::{Decodable, Encodable};
use sos_sdk::{
    commit::{CommitHash, CommitProof, Comparison},
    events::{AccountEvent, EventLogExt, EventLogType, WriteEvent},
    storage::StorageEventLogs,
    sync::{MaybeConflict, Patch, SyncPacket},
    vault::VaultId,
};
use tracing::instrument;

const PROOF_SCAN_LIMIT: u16 = 32;

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
            self.auto_merge_identity().await?;
        }

        if conflict.account {
            self.auto_merge_account().await?;
        }

        #[cfg(feature = "device")]
        if conflict.device {
            self.auto_merge_device().await?;
        }

        #[cfg(feature = "files")]
        if conflict.files {
            self.auto_merge_files().await?;
        }

        for (folder_id, _) in &conflict.folders {
            self.auto_merge_folder(&local, folder_id).await?;
        }

        Ok(())
    }

    async fn auto_merge_identity(&self) -> Result<()> {
        tracing::debug!("auto_merge::identity");

        let req = CommitScanRequest {
            log_type: EventLogType::Identity,
            offset: None,
            limit: PROOF_SCAN_LIMIT,
            ascending: false,
        };
        if let Some(ancestor_commit) = self.scan_proofs(req).await? {
            self.try_merge_from_ancestor::<WriteEvent>(
                EventLogType::Identity,
                ancestor_commit,
            )
            .await?;
        }

        Ok(())
    }

    async fn auto_merge_account(&self) -> Result<()> {
        tracing::debug!("auto_merge::account");

        let req = CommitScanRequest {
            log_type: EventLogType::Account,
            offset: None,
            limit: PROOF_SCAN_LIMIT,
            ascending: false,
        };
        if let Some(ancestor_commit) = self.scan_proofs(req).await? {
            self.try_merge_from_ancestor::<AccountEvent>(
                EventLogType::Account,
                ancestor_commit,
            )
            .await?;
        }

        Ok(())
    }

    #[cfg(feature = "device")]
    async fn auto_merge_device(&self) -> Result<()> {
        use sos_sdk::events::DeviceEvent;

        tracing::debug!("auto_merge::device");

        let req = CommitScanRequest {
            log_type: EventLogType::Device,
            offset: None,
            limit: PROOF_SCAN_LIMIT,
            ascending: false,
        };
        if let Some(ancestor_commit) = self.scan_proofs(req).await? {
            self.try_merge_from_ancestor::<DeviceEvent>(
                EventLogType::Device,
                ancestor_commit,
            )
            .await?;
        }

        Ok(())
    }

    #[cfg(feature = "files")]
    async fn auto_merge_files(&self) -> Result<()> {
        use sos_sdk::events::FileEvent;

        tracing::debug!("auto_merge::files");

        let req = CommitScanRequest {
            log_type: EventLogType::Files,
            offset: None,
            limit: PROOF_SCAN_LIMIT,
            ascending: false,
        };
        if let Some(ancestor_commit) = self.scan_proofs(req).await? {
            self.try_merge_from_ancestor::<FileEvent>(
                EventLogType::Files,
                ancestor_commit,
            )
            .await?;
        }

        Ok(())
    }

    async fn auto_merge_folder(
        &self,
        local: &SyncPacket,
        folder_id: &VaultId,
    ) -> Result<()> {
        tracing::debug!(folder_id = %folder_id, "auto_merge::folder");

        if local.status.folders.get(folder_id).is_some() {
            let req = CommitScanRequest {
                log_type: EventLogType::Folder(*folder_id),
                offset: None,
                limit: PROOF_SCAN_LIMIT,
                ascending: false,
            };
            if let Some(ancestor_commit) = self.scan_proofs(req).await? {
                self.try_merge_from_ancestor::<WriteEvent>(
                    EventLogType::Folder(*folder_id),
                    ancestor_commit,
                )
                .await?;
            }
        } else {
            tracing::warn!("local folder not found for auto_merge");
        }
        Ok(())
    }

    /// Try to merge from a shared ancestor commit.
    async fn try_merge_from_ancestor<T>(
        &self,
        log_type: EventLogType,
        commit: CommitHash,
    ) -> Result<()>
    where
        T: Default + Encodable + Decodable + Send + Sync,
    {
        tracing::debug!(commit = %commit, "auto_merge::try_merge_from_ancestor");

        // Fetch the patch of remote events
        let request = CommitDiffRequest {
            log_type,
            from_hash: commit,
        };

        // Get the patches from local and remote
        let account = self.account.lock().await;
        match &log_type {
            EventLogType::Identity => {
                let log = account.identity_log().await?;
                let event_log = log.read().await;
                let local_patch = event_log.diff(Some(&commit)).await?;
                if let Some(remote_patch) =
                    self.client.diff::<WriteEvent>(&request).await?.patch
                {
                    tracing::info!(
                        local_len = local_patch.len(),
                        remote_len = remote_patch.len(),
                        "auto_merge::identity",
                    );

                    let new_patch = self
                        .auto_merge_patches(local_patch, remote_patch)
                        .await?;
                } else {
                    tracing::warn!(
                        "auto_merge::identity::remote_patch_empty"
                    );
                }
            }
            EventLogType::Account => {
                let log = account.account_log().await?;
                let event_log = log.read().await;
                let local_patch = event_log.diff(Some(&commit)).await?;
                if let Some(remote_patch) =
                    self.client.diff::<AccountEvent>(&request).await?.patch
                {
                    tracing::info!(
                        local_len = local_patch.len(),
                        remote_len = remote_patch.len(),
                        "auto_merge::account",
                    );

                    let new_patch = self
                        .auto_merge_patches(local_patch, remote_patch)
                        .await?;
                } else {
                    tracing::warn!("auto_merge::account::remote_patch_empty");
                }
            }
            #[cfg(feature = "device")]
            EventLogType::Device => {
                use sos_sdk::events::DeviceEvent;

                let log = account.device_log().await?;
                let event_log = log.read().await;
                let local_patch = event_log.diff(Some(&commit)).await?;
                if let Some(remote_patch) =
                    self.client.diff::<DeviceEvent>(&request).await?.patch
                {
                    tracing::info!(
                        local_len = local_patch.len(),
                        remote_len = remote_patch.len(),
                        "auto_merge::device",
                    );

                    let new_patch = self
                        .auto_merge_patches(local_patch, remote_patch)
                        .await?;
                } else {
                    tracing::warn!("auto_merge::device::remote_patch_empty");
                }
            }
            #[cfg(feature = "files")]
            EventLogType::Files => {
                use sos_sdk::events::FileEvent;

                let log = account.file_log().await?;
                let event_log = log.read().await;
                let local_patch = event_log.diff(Some(&commit)).await?;
                if let Some(remote_patch) =
                    self.client.diff::<FileEvent>(&request).await?.patch
                {
                    tracing::info!(
                        local_len = local_patch.len(),
                        remote_len = remote_patch.len(),
                        "auto_merge::files",
                    );

                    let new_patch = self
                        .auto_merge_patches(local_patch, remote_patch)
                        .await?;
                } else {
                    tracing::warn!("auto_merge::files::remote_patch_empty");
                }
            }
            EventLogType::Folder(id) => {
                let log = account.folder_log(id).await?;
                let event_log = log.read().await;
                let local_patch = event_log.diff(Some(&commit)).await?;
                if let Some(remote_patch) =
                    self.client.diff::<WriteEvent>(&request).await?.patch
                {
                    tracing::info!(
                        local_len = local_patch.len(),
                        remote_len = remote_patch.len(),
                        "auto_merge::identity",
                    );

                    let new_patch = self
                        .auto_merge_patches(local_patch, remote_patch)
                        .await?;
                } else {
                    tracing::warn!(
                      folder_id = %id,
                      "auto_merge::folder::remote_patch_empty",
                    );
                }
            }
            EventLogType::Noop => unreachable!(),
        }

        Ok(())
    }

    async fn auto_merge_patches<T>(
        &self,
        local: Patch<T>,
        remote: Patch<T>,
    ) -> Result<Patch<T>>
    where
        T: Default + Encodable + Decodable + Send + Sync,
    {
        todo!();
    }

    /// Scan the remote for proofs that match this client.
    #[async_recursion]
    async fn scan_proofs(
        &self,
        request: CommitScanRequest,
    ) -> Result<Option<CommitHash>> {
        tracing::debug!(request = ?request, "auto_merge::scan_proofs");

        let response = self.client.scan(&request).await?;
        if !response.proofs.is_empty() {
            // Proofs are returned in the event log order
            // but we always want to scan from the end of
            // the event log so reverse the iteration
            for proof in response.proofs.iter().rev() {
                let commit_hashes =
                    self.compare_proof(&request.log_type, proof).await?;

                // Find the last matching commit from the indices
                // to prove
                if let Some(commit_hash) = commit_hashes.last() {
                    return Ok(Some(*commit_hash));
                }
            }

            // Try to scan more proofs
            let mut req = request.clone();
            req.offset = Some(response.offset);
            self.scan_proofs(req).await
        } else {
            Ok(None)
        }
    }

    /// Determine if a local event log contains a proof
    /// received from the server.
    async fn compare_proof(
        &self,
        log_type: &EventLogType,
        proof: &CommitProof,
    ) -> Result<Vec<CommitHash>> {
        tracing::debug!(proof = ?proof, "auto_merge::compare_proof");

        let account = self.account.lock().await;
        let comparison = match &log_type {
            EventLogType::Identity => {
                let log = account.identity_log().await?;
                let event_log = log.read().await;
                event_log.tree().compare(proof)?
            }
            EventLogType::Account => {
                let log = account.account_log().await?;
                let event_log = log.read().await;
                event_log.tree().compare(proof)?
            }
            #[cfg(feature = "device")]
            EventLogType::Device => {
                let log = account.device_log().await?;
                let event_log = log.read().await;
                event_log.tree().compare(proof)?
            }
            #[cfg(feature = "files")]
            EventLogType::Files => {
                let log = account.file_log().await?;
                let event_log = log.read().await;
                event_log.tree().compare(proof)?
            }
            EventLogType::Folder(id) => {
                let log = account.folder_log(id).await?;
                let event_log = log.read().await;
                event_log.tree().compare(proof)?
            }
            EventLogType::Noop => unreachable!(),
        };

        tracing::debug!(
            comparison = ?comparison,
            "auto_merge::compare_proof",
        );

        if let Comparison::Contains(_, leaves) = comparison {
            let commits =
                leaves.into_iter().map(CommitHash).collect::<Vec<_>>();
            Ok(commits)
        } else {
            Ok(vec![])
        }
    }
}
