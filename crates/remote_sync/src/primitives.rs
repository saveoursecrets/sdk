//! Synchronization types that are used internally.
use indexmap::IndexMap;
use sos_core::{
    commit::Comparison,
    events::{patch::FolderDiff, EventLog},
    Origin, VaultId,
};
use sos_sync::{
    MaybeDiff, StorageEventLogs, SyncDiff, SyncStatus, SyncStorage,
};

#[cfg(feature = "files")]
use sos_core::events::patch::FileDiff;

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
    /// Comparison of the device event log.
    pub device: Comparison,
    /// Comparison of the files event log.
    #[cfg(feature = "files")]
    pub files: Option<Comparison>,
    /// Comparison for each folder in the account.
    pub folders: IndexMap<VaultId, Comparison>,
}

impl SyncComparison {
    /// Create a new sync comparison.
    pub async fn new<S, E>(
        storage: &S,
        remote_status: SyncStatus,
    ) -> std::result::Result<SyncComparison, E>
    where
        S: SyncStorage,
        E: From<<S as StorageEventLogs>::Error> + From<sos_core::Error>,
    {
        let local_status = storage.sync_status().await?;

        let identity = {
            let identity = storage.identity_log().await?;
            let reader = identity.read().await;
            reader.tree().compare(&remote_status.identity.1)?
        };

        let account = {
            let account = storage.account_log().await?;
            let reader = account.read().await;
            reader.tree().compare(&remote_status.account.1)?
        };

        let device = {
            let device = storage.device_log().await?;
            let reader = device.read().await;
            reader.tree().compare(&remote_status.device.1)?
        };

        #[cfg(feature = "files")]
        let files = {
            let files = storage.file_log().await?;
            let reader = files.read().await;
            if let Some(files) = &remote_status.files {
                if reader.tree().is_empty() {
                    None
                } else {
                    Some(reader.tree().compare(&files.1)?)
                }
            } else if reader.tree().is_empty() {
                None
            } else {
                Some(Comparison::Unknown)
            }
        };

        let folders = {
            let mut folders = IndexMap::new();
            for (id, folder) in &remote_status.folders {
                // Folder may exist on remote but not locally
                // if we have just deleted a folder
                if let Ok(event_log) = storage.folder_log(id).await {
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
            device,
            #[cfg(feature = "files")]
            files,
            folders,
        })
    }

    /// Determine if synchronization is required.
    pub fn needs_sync(&self) -> bool {
        self.local_status != self.remote_status
    }

    /// Build a diff from this comparison.
    ///
    /// The diff includes changes on local that are not yet
    /// present on the remote or information that will allow
    /// a comparison on the remote.
    pub async fn diff<S, E>(
        &self,
        storage: &S,
    ) -> std::result::Result<SyncDiff, E>
    where
        S: SyncStorage,
        E: std::error::Error
            + std::fmt::Debug
            + From<<S as StorageEventLogs>::Error>
            + From<sos_backend::Error>
            + From<sos_backend::StorageError>
            + From<sos_core::Error>,
    {
        let mut diff: SyncDiff = Default::default();

        match self.identity {
            Comparison::Equal => {}
            Comparison::Contains(_) => {
                // Need to push changes to remote
                let log = storage.identity_log().await?;
                let reader = log.read().await;
                let is_last_commit = Some(&self.remote_status.identity.0)
                    == reader.tree().last_commit().as_ref();

                // Avoid empty patches when commit is already the last
                if !is_last_commit {
                    let identity = reader
                        .diff_checked(
                            Some(self.remote_status.identity.0),
                            self.remote_status.identity.1.clone(),
                        )
                        .await?;
                    diff.identity = Some(MaybeDiff::Diff(identity));
                }
            }
            Comparison::Unknown => {
                tracing::info!(
                    local = ?self.local_status.identity,
                    remote = ?self.remote_status.identity,
                    "identity folder divergence"
                );

                diff.identity = Some(MaybeDiff::Compare(Some(
                    self.local_status.identity.clone(),
                )));
            }
        }

        match self.account {
            Comparison::Equal => {}
            Comparison::Contains(_) => {
                // Need to push changes to remote
                let log = storage.account_log().await?;
                let reader = log.read().await;

                let is_last_commit = Some(&self.remote_status.account.0)
                    == reader.tree().last_commit().as_ref();

                // Avoid empty patches when commit is already the last
                if !is_last_commit {
                    let account = reader
                        .diff_checked(
                            Some(self.remote_status.account.0),
                            self.remote_status.account.1.clone(),
                        )
                        .await?;
                    diff.account = Some(MaybeDiff::Diff(account));
                }
            }
            Comparison::Unknown => {
                tracing::info!(
                    local = ?self.local_status.account,
                    remote = ?self.remote_status.account,
                    "account events divergence"
                );

                diff.account = Some(MaybeDiff::Compare(Some(
                    self.local_status.account.clone(),
                )));
            }
        }

        match self.device {
            Comparison::Equal => {}
            Comparison::Contains(_) => {
                // Need to push changes to remote
                let log = storage.device_log().await?;
                let reader = log.read().await;

                let is_last_commit = Some(&self.remote_status.device.0)
                    == reader.tree().last_commit().as_ref();

                // Avoid empty patches when commit is already the last
                if !is_last_commit {
                    let device = reader
                        .diff_checked(
                            Some(self.remote_status.device.0),
                            self.remote_status.device.1.clone(),
                        )
                        .await?;
                    diff.device = Some(MaybeDiff::Diff(device));
                }
            }
            Comparison::Unknown => {
                tracing::info!(
                    local = ?self.local_status.device,
                    remote = ?self.remote_status.device,
                    "device events divergence"
                );

                // NOTE: this will break the device revoke test spec!
                /*
                diff.device = Some(MaybeDiff::Compare(Some(
                    self.local_status.device.clone(),
                )));
                */
            }
        }

        #[cfg(feature = "files")]
        match (&self.files, &self.remote_status.files) {
            (Some(files), Some(remote_files)) => {
                match files {
                    Comparison::Equal => {}
                    Comparison::Contains(_) => {
                        // Need to push changes to remote
                        let log = storage.file_log().await?;
                        let reader = log.read().await;

                        let is_last_commit = Some(&remote_files.0)
                            == reader.tree().last_commit().as_ref();

                        // Avoid empty patches when commit is already the last
                        if !is_last_commit {
                            let files = reader
                                .diff_checked(
                                    Some(remote_files.0),
                                    remote_files.1.clone(),
                                )
                                .await?;

                            diff.files = Some(MaybeDiff::Diff(files));
                        }
                    }
                    Comparison::Unknown => {
                        tracing::info!(
                            local = ?files,
                            remote = ?remote_files,
                            "file events divergence"
                        );

                        diff.files = Some(MaybeDiff::Compare(
                            self.local_status.files.clone(),
                        ));
                    }
                }
            }
            // Remote does not have any files yet so we need
            // to send the entire file event log
            (Some(Comparison::Unknown), None) => {
                // Need to push changes to remote
                let log = storage.file_log().await?;
                let reader = log.read().await;
                if !reader.tree().is_empty() {
                    let files = FileDiff {
                        last_commit: None,
                        patch: reader.diff_events(None).await?,
                        checkpoint: Default::default(),
                    };
                    diff.files = Some(MaybeDiff::Diff(files));
                }
            }
            _ => {}
        }

        for (id, folder) in &self.folders {
            let commit_state = self
                .remote_status
                .folders
                .get(id)
                .ok_or(sos_backend::StorageError::FolderNotFound(*id))?;

            match folder {
                Comparison::Equal => {}
                Comparison::Contains(_) => {
                    // Need to push changes to remote
                    let log = storage.folder_log(id).await?;
                    let log = log.read().await;
                    let folder = log
                        .diff_checked(
                            Some(commit_state.0),
                            commit_state.1.clone(),
                        )
                        .await?;

                    if !folder.patch.is_empty() {
                        diff.folders.insert(*id, MaybeDiff::Diff(folder));
                    }
                }
                Comparison::Unknown => {
                    tracing::info!(
                        id = %id,
                        local = ?self.local_status.folders.get(id),
                        remote = ?commit_state,
                        "folder events divergence"
                    );

                    diff.folders.insert(
                        *id,
                        MaybeDiff::Compare(
                            self.local_status.folders.get(id).cloned(),
                        ),
                    );
                }
            }
        }

        // Handle events for new folders on local that
        // don't exist on remote yet
        for (id, _) in &self.local_status.folders {
            if self.remote_status.folders.get(id).is_none() {
                let log = storage.folder_log(id).await?;
                let log = log.read().await;
                let first_commit = log.tree().first_commit()?;

                let folder = FolderDiff {
                    last_commit: Some(first_commit.0),
                    patch: log.diff_events(Some(&first_commit.0)).await?,
                    checkpoint: first_commit.1,
                };

                if !folder.patch.is_empty() {
                    diff.folders.insert(*id, MaybeDiff::Diff(folder));
                }
            }
        }

        Ok(diff)
    }
}

/// Difference between a local sync status and a remote
/// sync status.
pub async fn diff<S, E>(
    storage: &S,
    remote_status: SyncStatus,
) -> std::result::Result<(bool, SyncStatus, SyncDiff), E>
where
    S: SyncStorage,
    E: std::error::Error
        + std::fmt::Debug
        + From<<S as StorageEventLogs>::Error>
        + From<sos_core::Error>
        + From<sos_backend::Error>
        + From<sos_backend::StorageError>
        + Send
        + Sync
        + 'static,
{
    let comparison = {
        // Compare local status to the remote
        SyncComparison::new::<_, E>(storage, remote_status).await?
    };

    let needs_sync = comparison.needs_sync();
    let mut diff = comparison.diff::<_, E>(storage).await?;

    let is_server = !storage.is_client_storage();
    if is_server {
        let storage_folders = storage.folder_details().await?;
        diff.folders.retain(|k, _| {
            if let Some(folder) = storage_folders.iter().find(|s| s.id() == k)
            {
                !folder.flags().is_sync_disabled()
            } else {
                true
            }
        });
    }

    Ok((needs_sync, comparison.local_status, diff))
}
