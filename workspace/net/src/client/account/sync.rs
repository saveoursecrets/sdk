//! Adds sync capability to network account.
use crate::client::{
    Error, NetworkAccount, RemoteSync, Remotes, Result, SyncError,
    SyncOptions,
};
use async_trait::async_trait;
use sos_sdk::{
    account::{AccountHandler, BeforeChange},
    commit::CommitState,
    events::Event,
    storage::Storage,
    sync::SyncStatus,
    vault::Summary,
};
use std::{any::Any, sync::Arc};
use tokio::sync::RwLock;

pub(super) type SyncHandlerData = Arc<RwLock<Remotes>>;

pub(super) struct SyncHandler {
    pub(super) remotes: Arc<RwLock<Remotes>>,
}

#[async_trait::async_trait]
impl AccountHandler for SyncHandler {
    type Data = SyncHandlerData;

    async fn before_change(&self, data: &BeforeChange) {
        let remotes = self.remotes.read().await;
        for remote in remotes.values() {
            if let Some(e) = remote.sync().await {
                tracing::error!(error = ?e, "failed to sync before change");
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

    /*
    async fn pull(
        &self,
        local_status: &SyncStatus,
        options: &SyncOptions,
    ) -> std::result::Result<SyncStatus, SyncError> {
        let _ = self.sync_lock.lock().await;
        let mut errors = Vec::new();
        let remotes = self.remotes.read().await;

        let mut new_status: Option<SyncStatus> = None;
        for (origin, remote) in &*remotes {
            let sync_remote = options.origins.is_empty()
                || options.origins.contains(origin);

            let status = if let Some(updated_status) = &new_status {
                updated_status
            } else {
                local_status
            };

            if sync_remote {
                match remote.pull(status, options).await {
                    Ok(updated_status) => new_status = Some(updated_status),
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
            Ok(new_status.unwrap_or_else(|| local_status.clone()))
        } else {
            for error in &errors {
                tracing::error!(error = ?error);
            }
            Err(SyncError::Multiple(errors))
        }
    }
    */

    /*
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
    */

    /*
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
    */

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }

    fn as_any_mut(&mut self) -> &mut (dyn Any + Send + Sync) {
        self
    }
}
