use crate::{BackendTarget, Error};
use async_trait::async_trait;
use binary_stream::futures::{Decodable, Encodable};
use futures::stream::BoxStream;
use sos_core::{
    commit::{CommitHash, CommitProof, CommitTree},
    events::{
        patch::{CheckedPatch, Diff, Patch},
        AccountEvent, DeviceEvent, EventLog, EventRecord, WriteEvent,
    },
    AccountId, VaultId,
};
use sos_database::{async_sqlite::Client, DatabaseEventLog};
use sos_filesystem::FileSystemEventLog;
use std::path::Path;

/// Event log for account events.
pub type BackendAccountEventLog = BackendEventLog<AccountEvent>;
/// Event log for device events.
pub type BackendDeviceEventLog = BackendEventLog<DeviceEvent>;
/// Event log for folder events.
pub type BackendFolderEventLog = BackendEventLog<WriteEvent>;

#[cfg(feature = "files")]
/// Event log for file events.
pub type BackendFileEventLog = BackendEventLog<sos_core::events::FileEvent>;

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
        match target {
            BackendTarget::FileSystem(paths) => {
                Self::new_fs_account(paths.account_events()).await
            }
            BackendTarget::Database(_, client) => {
                Self::new_db_account(client, *account_id).await
            }
        }
    }

    /// Create a file system account event log.
    // TODO: make this private
    pub async fn new_fs_account<P: AsRef<Path>>(
        path: P,
    ) -> Result<Self, Error> {
        Ok(BackendEventLog::FileSystem(
            FileSystemEventLog::<AccountEvent, Error>::new_account(path)
                .await?,
        ))
    }

    /// Create a database account event log.
    // TODO: make this private
    pub async fn new_db_account(
        client: Client,
        account_id: AccountId,
    ) -> Result<Self, Error> {
        Ok(BackendEventLog::Database(
            DatabaseEventLog::<AccountEvent, Error>::new_account(
                client, account_id,
            )
            .await?,
        ))
    }
}

impl BackendEventLog<WriteEvent> {
    /// Create a new folder event log.
    pub async fn new_folder(
        target: BackendTarget,
        account_id: &AccountId,
        folder_id: &VaultId,
    ) -> Result<Self, Error> {
        match target {
            BackendTarget::FileSystem(paths) => {
                Self::new_fs_folder(paths.event_log_path(folder_id)).await
            }
            BackendTarget::Database(_, client) => {
                Self::new_db_folder(client, *account_id, *folder_id).await
            }
        }
    }

    /// Create a file system folder event log.
    // TODO: make this private
    pub async fn new_fs_folder<P: AsRef<Path>>(
        path: P,
    ) -> Result<Self, Error> {
        Ok(BackendEventLog::FileSystem(
            FileSystemEventLog::<WriteEvent, Error>::new_folder(path).await?,
        ))
    }

    /// Create a database folder event log.
    // TODO: make this private
    pub async fn new_db_folder(
        client: Client,
        account_id: AccountId,
        folder_id: VaultId,
    ) -> Result<Self, Error> {
        Ok(BackendEventLog::Database(
            DatabaseEventLog::<WriteEvent, Error>::new_folder(
                client, account_id, folder_id,
            )
            .await?,
        ))
    }
}

impl BackendEventLog<DeviceEvent> {
    /// Create a new device event log.
    pub async fn new_device(
        target: BackendTarget,
        account_id: &AccountId,
    ) -> Result<Self, Error> {
        match target {
            BackendTarget::FileSystem(paths) => {
                Self::new_fs_device(paths.device_events()).await
            }
            BackendTarget::Database(_, client) => {
                Self::new_db_device(client, *account_id).await
            }
        }
    }

    /// Create a file system device event log.
    // TODO: make this private
    pub async fn new_fs_device<P: AsRef<Path>>(
        path: P,
    ) -> Result<Self, Error> {
        Ok(BackendEventLog::FileSystem(
            FileSystemEventLog::<DeviceEvent, Error>::new_device(path)
                .await?,
        ))
    }

    /// Create a database device event log.
    // TODO: make this private
    pub async fn new_db_device(
        client: Client,
        account_id: AccountId,
    ) -> Result<Self, Error> {
        Ok(BackendEventLog::Database(
            DatabaseEventLog::<DeviceEvent, Error>::new_device(
                client, account_id,
            )
            .await?,
        ))
    }
}

#[cfg(feature = "files")]
impl BackendEventLog<FileEvent> {
    /// Create a new file event log.
    pub async fn new_file(
        target: BackendTarget,
        account_id: &AccountId,
    ) -> Result<Self, Error> {
        match target {
            BackendTarget::FileSystem(paths) => {
                Self::new_fs_file(paths.file_events()).await
            }
            BackendTarget::Database(_, client) => {
                Self::new_db_file(client, *account_id).await
            }
        }
    }

    /// Create a file system file event log.
    pub async fn new_fs_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        Ok(BackendEventLog::FileSystem(
            FileSystemEventLog::<FileEvent, Error>::new_file(path).await?,
        ))
    }

    /// Create a database file event log.
    pub async fn new_db_file(
        client: Client,
        account_id: AccountId,
    ) -> Result<Self, Error> {
        Ok(BackendEventLog::Database(
            DatabaseEventLog::<FileEvent, Error>::new_file(
                client, account_id,
            )
            .await?,
        ))
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

    async fn apply(&mut self, events: &[T]) -> Result<(), Self::Error> {
        match self {
            Self::Database(inner) => inner.apply(events).await,
            Self::FileSystem(inner) => inner.apply(events).await,
        }
    }

    async fn apply_records(
        &mut self,
        records: Vec<EventRecord>,
    ) -> Result<(), Self::Error> {
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
    ) -> Result<(), Self::Error> {
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
