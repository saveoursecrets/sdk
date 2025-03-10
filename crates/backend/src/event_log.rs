use crate::{BackendTarget, Error};
use async_trait::async_trait;
use binary_stream::futures::{Decodable, Encodable};
use futures::stream::BoxStream;
use sos_core::{
    commit::{CommitHash, CommitProof, CommitSpan, CommitTree},
    events::{
        patch::{CheckedPatch, Diff, Patch},
        AccountEvent, DeviceEvent, EventLog, EventRecord, WriteEvent,
    },
    AccountId, VaultId,
};
use sos_database::{
    entity::{AccountEntity, FolderEntity, FolderRecord},
    DatabaseEventLog,
};
use sos_filesystem::FileSystemEventLog;

/// Event log for account events.
pub type AccountEventLog = BackendEventLog<AccountEvent>;
/// Event log for device events.
pub type DeviceEventLog = BackendEventLog<DeviceEvent>;
/// Event log for folder events.
pub type FolderEventLog = BackendEventLog<WriteEvent>;
/// Event log for file events.
#[cfg(feature = "files")]
pub type FileEventLog = BackendEventLog<sos_core::events::FileEvent>;

#[cfg(feature = "files")]
use sos_core::events::FileEvent;

/// Generic event log.
pub enum BackendEventLog<T>
where
    T: Default + Encodable + Decodable + Send + Sync,
{
    /// Database event log.
    Database(DatabaseEventLog<T, Error>),
    /// File system event log.
    FileSystem(FileSystemEventLog<T, Error>),
}

impl BackendEventLog<AccountEvent> {
    /// Create a new account event log.
    pub async fn new_account(
        target: BackendTarget,
        account_id: &AccountId,
    ) -> Result<Self, Error> {
        Ok(match target {
            BackendTarget::FileSystem(paths) => BackendEventLog::FileSystem(
                FileSystemEventLog::<AccountEvent, Error>::new_account(
                    paths.with_account_id(account_id).account_events(),
                )
                .await?,
            ),
            BackendTarget::Database(_, client) => BackendEventLog::Database(
                DatabaseEventLog::<AccountEvent, Error>::new_account(
                    client,
                    *account_id,
                )
                .await?,
            ),
        })
    }
}

impl BackendEventLog<WriteEvent> {
    /// Create a new folder event log.
    pub async fn new_folder(
        target: BackendTarget,
        account_id: &AccountId,
        folder_id: &VaultId,
    ) -> Result<Self, Error> {
        Ok(match target {
            BackendTarget::FileSystem(paths) => BackendEventLog::FileSystem(
                FileSystemEventLog::<WriteEvent, Error>::new_folder(
                    paths
                        .with_account_id(account_id)
                        .event_log_path(folder_id),
                )
                .await?,
            ),
            BackendTarget::Database(_, client) => BackendEventLog::Database(
                DatabaseEventLog::<WriteEvent, Error>::new_folder(
                    client,
                    *account_id,
                    *folder_id,
                )
                .await?,
            ),
        })
    }

    /// Create a new login event log.
    pub async fn new_login_folder(
        target: BackendTarget,
        account_id: &AccountId,
    ) -> Result<Self, Error> {
        Ok(match target {
            BackendTarget::FileSystem(paths) => BackendEventLog::FileSystem(
                FileSystemEventLog::<WriteEvent, Error>::new_folder(
                    paths.with_account_id(account_id).identity_events(),
                )
                .await?,
            ),
            BackendTarget::Database(_, client) => {
                let account_id = *account_id;
                let folder_row = client
                    .conn_and_then(move |conn| {
                        let account_entity = AccountEntity::new(&conn);
                        let account_row =
                            account_entity.find_one(&account_id)?;
                        let folder_entity = FolderEntity::new(&conn);
                        folder_entity.find_login_folder(account_row.row_id)
                    })
                    .await?;
                let folder_record =
                    FolderRecord::from_row(folder_row).await?;
                BackendEventLog::Database(
                    DatabaseEventLog::<WriteEvent, Error>::new_folder(
                        client,
                        account_id,
                        *folder_record.summary.id(),
                    )
                    .await?,
                )
            }
        })
    }
}

impl BackendEventLog<DeviceEvent> {
    /// Create a new device event log.
    pub async fn new_device(
        target: BackendTarget,
        account_id: &AccountId,
    ) -> Result<Self, Error> {
        Ok(match target {
            BackendTarget::FileSystem(paths) => BackendEventLog::FileSystem(
                FileSystemEventLog::<DeviceEvent, Error>::new_device(
                    paths.with_account_id(account_id).device_events(),
                )
                .await?,
            ),
            BackendTarget::Database(_, client) => BackendEventLog::Database(
                DatabaseEventLog::<DeviceEvent, Error>::new_device(
                    client,
                    *account_id,
                )
                .await?,
            ),
        })
    }
}

#[cfg(feature = "files")]
impl BackendEventLog<FileEvent> {
    /// Create a new file event log.
    pub async fn new_file(
        target: BackendTarget,
        account_id: &AccountId,
    ) -> Result<Self, Error> {
        Ok(match target {
            BackendTarget::FileSystem(paths) => BackendEventLog::FileSystem(
                FileSystemEventLog::<FileEvent, Error>::new_file(
                    paths.with_account_id(account_id).file_events(),
                )
                .await?,
            ),
            BackendTarget::Database(_, client) => BackendEventLog::Database(
                DatabaseEventLog::<FileEvent, Error>::new_file(
                    client,
                    *account_id,
                )
                .await?,
            ),
        })
    }
}

#[async_trait]
impl<T> EventLog<T> for BackendEventLog<T>
where
    T: Default + Encodable + Decodable + Send + Sync + 'static,
{
    type Error = Error;

    async fn record_stream(
        &self,
        reverse: bool,
    ) -> BoxStream<'async_trait, Result<EventRecord, Self::Error>> {
        match self {
            Self::Database(inner) => inner.record_stream(reverse).await,
            Self::FileSystem(inner) => inner.record_stream(reverse).await,
        }
    }

    async fn event_stream(
        &self,
        reverse: bool,
    ) -> BoxStream<'async_trait, Result<(EventRecord, T), Self::Error>> {
        match self {
            Self::Database(inner) => inner.event_stream(reverse).await,
            Self::FileSystem(inner) => inner.event_stream(reverse).await,
        }
    }

    async fn diff_checked(
        &self,
        commit: Option<CommitHash>,
        checkpoint: CommitProof,
    ) -> Result<Diff<T>, Self::Error> {
        match self {
            Self::Database(inner) => {
                inner.diff_checked(commit, checkpoint).await
            }
            Self::FileSystem(inner) => {
                inner.diff_checked(commit, checkpoint).await
            }
        }
    }

    async fn diff_unchecked(&self) -> Result<Diff<T>, Self::Error> {
        match self {
            Self::Database(inner) => inner.diff_unchecked().await,
            Self::FileSystem(inner) => inner.diff_unchecked().await,
        }
    }

    async fn diff_events(
        &self,
        commit: Option<&CommitHash>,
    ) -> Result<Patch<T>, Self::Error> {
        match self {
            Self::Database(inner) => inner.diff_events(commit).await,
            Self::FileSystem(inner) => inner.diff_events(commit).await,
        }
    }

    fn tree(&self) -> &CommitTree {
        match self {
            Self::Database(inner) => inner.tree(),
            Self::FileSystem(inner) => inner.tree(),
        }
    }

    /*
    fn identity(&self) -> &'static [u8] {
        match self {
            Self::Database(inner) => inner.identity(),
            Self::FileSystem(inner) => inner.identity(),
        }
    }

    fn version(&self) -> Option<u16> {
        match self {
            Self::Database(inner) => inner.version(),
            Self::FileSystem(inner) => inner.version(),
        }
    }
    */

    /*
    async fn truncate(&mut self) -> Result<(), Self::Error> {
        match self {
            Self::Database(inner) => inner.truncate().await,
            Self::FileSystem(inner) => inner.truncate().await,
        }
    }
    */

    async fn rewind(
        &mut self,
        commit: &CommitHash,
    ) -> Result<Vec<EventRecord>, Self::Error> {
        match self {
            Self::Database(inner) => inner.rewind(commit).await,
            Self::FileSystem(inner) => inner.rewind(commit).await,
        }
    }

    async fn load_tree(&mut self) -> Result<(), Self::Error> {
        match self {
            Self::Database(inner) => inner.load_tree().await,
            Self::FileSystem(inner) => inner.load_tree().await,
        }
    }

    async fn clear(&mut self) -> Result<(), Self::Error> {
        match self {
            Self::Database(inner) => inner.clear().await,
            Self::FileSystem(inner) => inner.clear().await,
        }
    }

    async fn apply(
        &mut self,
        events: &[T],
    ) -> Result<CommitSpan, Self::Error> {
        match self {
            Self::Database(inner) => inner.apply(events).await,
            Self::FileSystem(inner) => inner.apply(events).await,
        }
    }

    async fn apply_records(
        &mut self,
        records: Vec<EventRecord>,
    ) -> Result<CommitSpan, Self::Error> {
        match self {
            Self::Database(inner) => inner.apply_records(records).await,
            Self::FileSystem(inner) => inner.apply_records(records).await,
        }
    }

    async fn patch_checked(
        &mut self,
        commit_proof: &CommitProof,
        patch: &Patch<T>,
    ) -> Result<CheckedPatch, Self::Error> {
        match self {
            Self::Database(inner) => {
                inner.patch_checked(commit_proof, patch).await
            }
            Self::FileSystem(inner) => {
                inner.patch_checked(commit_proof, patch).await
            }
        }
    }

    async fn replace_all_events(
        &mut self,
        diff: &Diff<T>,
    ) -> Result<(), Self::Error> {
        match self {
            Self::Database(inner) => inner.replace_all_events(diff).await,
            Self::FileSystem(inner) => inner.replace_all_events(diff).await,
        }
    }

    async fn patch_unchecked(
        &mut self,
        patch: &Patch<T>,
    ) -> Result<CommitSpan, Self::Error> {
        match self {
            Self::Database(inner) => inner.patch_unchecked(patch).await,
            Self::FileSystem(inner) => inner.patch_unchecked(patch).await,
        }
    }

    async fn diff_records(
        &self,
        commit: Option<&CommitHash>,
    ) -> Result<Vec<EventRecord>, Self::Error> {
        match self {
            Self::Database(inner) => inner.diff_records(commit).await,
            Self::FileSystem(inner) => inner.diff_records(commit).await,
        }
    }

    fn version(&self) -> u16 {
        match self {
            Self::Database(inner) => inner.version(),
            Self::FileSystem(inner) => inner.version(),
        }
    }
}
