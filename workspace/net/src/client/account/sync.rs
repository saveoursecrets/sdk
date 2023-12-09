//! Adds sync capability to network account.
use crate::client::{
    Error, NetworkAccount, RemoteSync, Remotes, Result, SyncError,
    SyncOptions,
};
use async_trait::async_trait;
use sos_sdk::{
    account::AccountHandler, commit::CommitState, events::Event,
    storage::FolderStorage, vault::Summary,
};
use std::{any::Any, sync::Arc};
use tokio::sync::RwLock;

pub(super) type SyncHandlerData = Arc<RwLock<Remotes>>;

pub(super) struct SyncHandler {
    pub(super) remotes: Arc<RwLock<Remotes>>,
}

impl SyncHandler {
    /// Try to sync the target folder against all remotes.
    async fn try_sync_folder(
        &self,
        storage: Arc<RwLock<FolderStorage>>,
        folder: &Summary,
        commit_state: &CommitState,
    ) -> Result<Option<CommitState>> {
        let mut changed = false;
        let (last_commit, commit_proof) = commit_state;
        let mut last_commit = last_commit.clone();
        let mut commit_proof = commit_proof.clone();

        let remotes = self.remotes.read().await;
        for remote in remotes.values() {
            let local_changed = remote
                .sync_folder(folder, commit_state, None, &Default::default())
                .await?;

            // If a remote changes were applied to local
            // we need to recompute the last commit and client proof
            if local_changed {
                let reader = storage.read().await;
                let event_log = reader
                    .cache()
                    .get(folder.id())
                    .ok_or(Error::CacheNotAvailable(*folder.id()))?;
                last_commit = event_log
                    .last_commit()
                    .await?
                    .ok_or(Error::NoRootCommit)?;
                commit_proof = event_log.tree().head()?;
            }

            changed = changed || local_changed;
        }

        Ok(if changed {
            Some((last_commit, commit_proof))
        } else {
            None
        })
    }
}

#[async_trait::async_trait]
impl AccountHandler for SyncHandler {
    type Data = SyncHandlerData;

    async fn before_change(
        &self,
        storage: Arc<RwLock<FolderStorage>>,
        folder: &Summary,
        commit_state: &CommitState,
    ) -> Option<CommitState> {
        match self.try_sync_folder(storage, folder, commit_state).await {
            Ok(commit_state) => commit_state,
            Err(e) => {
                tracing::error!(error = ?e, "failed to sync before change");
                None
            }
        }
    }
}

#[async_trait]
impl RemoteSync for NetworkAccount {
    async fn sync(&self) -> Option<SyncError> {
        self.sync_with_options(&Default::default()).await
    }

    async fn sync_with_options(
        &self,
        options: &SyncOptions,
    ) -> Option<SyncError> {
        let _ = self.sync_lock.lock().await;
        let mut errors = Vec::new();
        let remotes = self.remotes.read().await;
        for (origin, remote) in &*remotes {
            let sync_remote = options.origins.is_empty()
                || options.origins.contains(origin);

            if sync_remote {
                if let Some(e) = remote.sync_with_options(options).await {
                    match e {
                        SyncError::One(e) => errors.push((origin.clone(), e)),
                        SyncError::Multiple(mut errs) => {
                            errors.append(&mut errs)
                        }
                    }
                }
            }
        }
        if errors.is_empty() {
            None
        } else {
            for error in &errors {
                tracing::error!(error = ?error);
            }
            Some(SyncError::Multiple(errors))
        }
    }

    async fn sync_folder(
        &self,
        folder: &Summary,
        commit_state: &CommitState,
        remote_state: Option<CommitState>,
        options: &SyncOptions,
    ) -> std::result::Result<bool, SyncError> {
        let _ = self.sync_lock.lock().await;
        let mut errors = Vec::new();
        let mut changed = false;
        let remotes = self.remotes.read().await;
        for (origin, remote) in &*remotes {
            let sync_remote = options.origins.is_empty()
                || options.origins.contains(origin);

            if sync_remote {
                match remote
                    .sync_folder(
                        folder,
                        commit_state,
                        remote_state.clone(),
                        options,
                    )
                    .await
                {
                    Ok(changes) => changed = changed || changes,
                    Err(e) => match e {
                        SyncError::One(e) => errors.push((origin.clone(), e)),
                        SyncError::Multiple(mut errs) => {
                            errors.append(&mut errs)
                        }
                    },
                }
            }
        }
        if errors.is_empty() {
            Ok(changed)
        } else {
            for error in &errors {
                tracing::error!(error = ?error);
            }
            Err(SyncError::Multiple(errors))
        }
    }

    async fn sync_send_events(
        &self,
        folder: &Summary,
        commit_state: &CommitState,
        events: &[Event],
    ) -> std::result::Result<(), SyncError> {
        let _ = self.sync_lock.lock().await;
        let mut errors = Vec::new();
        let remotes = self.remotes.read().await;
        for (origin, remote) in &*remotes {
            if let Err(e) =
                remote.sync_send_events(folder, commit_state, events).await
            {
                match e {
                    SyncError::One(e) => errors.push((origin.clone(), e)),
                    SyncError::Multiple(mut errs) => errors.append(&mut errs),
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(SyncError::Multiple(errors))
        }
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }

    fn as_any_mut(&mut self) -> &mut (dyn Any + Send + Sync) {
        self
    }
}
