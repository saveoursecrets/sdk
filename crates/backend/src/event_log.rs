use crate::Error;
use async_trait::async_trait;
use binary_stream::futures::{Decodable, Encodable};
use futures::stream::BoxStream;
use sos_core::{
    commit::{CommitHash, CommitProof, CommitTree},
    events::{
        patch::{CheckedPatch, Diff, Patch},
        AccountEvent, DeviceEvent, EventLog, EventRecord, WriteEvent,
    },
};
use sos_filesystem::events::FileSystemEventLog;
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

/// Generic event log.
pub enum BackendEventLog<T>
where
    T: Default + Encodable + Decodable + Send + Sync,
{
    /// File system event log.
    FileSystem(FileSystemEventLog<T, Error>),
}

impl<T> BackendEventLog<T>
where
    T: Default + Encodable + Decodable + Send + Sync + 'static,
{
    /// Create a file system folder event log.
    pub async fn new_fs_folder<P: AsRef<Path>>(
        path: P,
    ) -> Result<Self, Error> {
        todo!();
    }

    /// Create a file system account event log.
    pub async fn new_fs_account<P: AsRef<Path>>(
        path: P,
    ) -> Result<Self, Error> {
        todo!();
    }

    /// Create a file system device event log.
    pub async fn new_fs_device<P: AsRef<Path>>(
        path: P,
    ) -> Result<Self, Error> {
        todo!();
    }

    #[cfg(feature = "files")]
    /// Create a file system file event log.
    pub async fn new_fs_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        todo!();
    }
}

#[async_trait]
impl<T> EventLog<T> for BackendEventLog<T>
where
    T: Default + Encodable + Decodable + Send + Sync + 'static,
{
    type Error = Error;

    async fn stream(
        &self,
        reverse: bool,
    ) -> BoxStream<'static, Result<(EventRecord, T), Self::Error>> {
        todo!();
    }

    async fn diff_checked(
        &self,
        commit: Option<CommitHash>,
        checkpoint: CommitProof,
    ) -> Result<Diff<T>, Self::Error> {
        todo!();
    }

    async fn diff_unchecked(&self) -> Result<Diff<T>, Self::Error> {
        todo!();
    }

    async fn diff_events(
        &self,
        commit: Option<&CommitHash>,
    ) -> Result<Patch<T>, Self::Error> {
        todo!();
    }

    fn tree(&self) -> &CommitTree {
        todo!();
    }

    fn identity(&self) -> &'static [u8] {
        todo!();
    }

    fn version(&self) -> Option<u16> {
        todo!();
    }

    async fn truncate(&mut self) -> Result<(), Self::Error> {
        todo!();
    }

    async fn rewind(
        &mut self,
        commit: &CommitHash,
    ) -> Result<Vec<EventRecord>, Self::Error> {
        todo!();
    }

    async fn load_tree(&mut self) -> Result<(), Self::Error> {
        todo!();
    }

    async fn clear(&mut self) -> Result<(), Self::Error> {
        todo!();
    }

    async fn apply(&mut self, events: Vec<&T>) -> Result<(), Self::Error> {
        todo!();
    }

    async fn apply_records(
        &mut self,
        records: Vec<EventRecord>,
    ) -> Result<(), Self::Error> {
        todo!();
    }

    async fn patch_checked(
        &mut self,
        commit_proof: &CommitProof,
        patch: &Patch<T>,
    ) -> Result<CheckedPatch, Self::Error> {
        todo!();
    }

    async fn patch_replace(
        &mut self,
        diff: &Diff<T>,
    ) -> Result<(), Self::Error> {
        todo!();
    }

    async fn patch_unchecked(
        &mut self,
        patch: &Patch<T>,
    ) -> Result<(), Self::Error> {
        todo!();
    }

    async fn diff_records(
        &self,
        commit: Option<&CommitHash>,
    ) -> Result<Vec<EventRecord>, Self::Error> {
        todo!();
    }

    #[doc(hidden)]
    async fn read_file_version(&self) -> Result<u16, Self::Error> {
        todo!();
    }
}
