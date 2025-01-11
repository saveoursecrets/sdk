//! Event log backed by a database table.
use crate::{
    db::{CommitRecord, EventEntity},
    Error,
};
use async_sqlite::Client;
use async_trait::async_trait;
use binary_stream::futures::{Decodable, Encodable};
use futures::stream::BoxStream;
use sos_core::{
    commit::{CommitHash, CommitProof, CommitTree},
    events::{
        patch::{CheckedPatch, Diff, Patch},
        AccountEvent, DeviceEvent, EventLog, EventRecord, WriteEvent,
    },
    VaultId,
};

#[cfg(feature = "files")]
use sos_core::events::FileEvent;

/// Database event log.
pub struct DatabaseEventLog<T, E>
where
    T: Default + Encodable + Decodable + Send + Sync,
    E: std::error::Error
        + std::fmt::Debug
        + From<sos_core::Error>
        + From<crate::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    folder_id: VaultId,
    client: Client,
    ids: Vec<i64>,
    tree: CommitTree,
    marker: std::marker::PhantomData<(T, E)>,
}

impl<E> DatabaseEventLog<AccountEvent, E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<sos_core::Error>
        + From<crate::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    /// Create a new account event log.
    pub fn new_account(client: Client, folder_id: VaultId) -> Self {
        Self {
            folder_id,
            client,
            ids: Vec::new(),
            tree: CommitTree::new(),
            marker: std::marker::PhantomData,
        }
    }
}

impl<E> DatabaseEventLog<WriteEvent, E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<sos_core::Error>
        + From<crate::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    /// Create a new folder event log.
    pub fn new_folder(client: Client, folder_id: VaultId) -> Self {
        Self {
            folder_id,
            client,
            ids: Vec::new(),
            tree: CommitTree::new(),
            marker: std::marker::PhantomData,
        }
    }
}

impl<E> DatabaseEventLog<DeviceEvent, E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<sos_core::Error>
        + From<crate::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    /// Create a new device event log.
    pub fn new_device(client: Client, folder_id: VaultId) -> Self {
        Self {
            folder_id,
            client,
            ids: Vec::new(),
            tree: CommitTree::new(),
            marker: std::marker::PhantomData,
        }
    }
}

#[cfg(feature = "files")]
impl<E> DatabaseEventLog<FileEvent, E>
where
    E: std::error::Error
        + std::fmt::Debug
        + From<sos_core::Error>
        + From<crate::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    /// Create a new file event log.
    pub fn new_file(client: Client, folder_id: VaultId) -> Self {
        Self {
            folder_id,
            client,
            ids: Vec::new(),
            tree: CommitTree::new(),
            marker: std::marker::PhantomData,
        }
    }
}

#[async_trait]
impl<T, E> EventLog<T> for DatabaseEventLog<T, E>
where
    T: Default + Encodable + Decodable + Send + Sync + 'static,
    E: std::error::Error
        + std::fmt::Debug
        + From<sos_core::Error>
        + From<crate::Error>
        + From<std::io::Error>
        + Send
        + Sync
        + 'static,
{
    type Error = E;

    async fn record_stream(
        &self,
        reverse: bool,
    ) -> BoxStream<'static, Result<EventRecord, Self::Error>> {
        todo!();
    }

    async fn event_stream(
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
        let patch = self.diff_events(None).await?;
        Ok(Diff::<T> {
            last_commit: None,
            patch,
            checkpoint: self.tree().head()?,
        })
    }

    async fn diff_events(
        &self,
        commit: Option<&CommitHash>,
    ) -> Result<Patch<T>, Self::Error> {
        let records = self.diff_records(commit).await?;
        Ok(Patch::new(records))
    }

    fn tree(&self) -> &CommitTree {
        &self.tree
    }

    async fn rewind(
        &mut self,
        commit: &CommitHash,
    ) -> Result<Vec<EventRecord>, Self::Error> {
        todo!();
    }

    async fn load_tree(&mut self) -> Result<(), Self::Error> {
        let folder_id = self.folder_id.clone();
        let commits = self
            .client
            .conn(move |conn| {
                let events = EventEntity::new(&conn);
                let commits = events.load_commits(&folder_id)?;
                Ok(commits)
            })
            .await
            .map_err(Error::from)?;
        for commit in commits {
            let record: CommitRecord = commit.try_into()?;
            self.ids.push(record.row_id);
            self.tree.insert(*record.commit_hash.as_ref());
        }
        self.tree.commit();
        Ok(())
    }

    async fn clear(&mut self) -> Result<(), Self::Error> {
        let folder_id = self.folder_id.clone();
        self.client
            .conn(move |conn| {
                let events = EventEntity::new(&conn);
                events.delete_all_events(&folder_id)?;
                Ok(())
            })
            .await
            .map_err(Error::from)?;
        self.tree = CommitTree::new();
        self.ids = Vec::new();
        Ok(())
    }

    async fn apply(&mut self, events: Vec<&T>) -> Result<(), Self::Error> {
        let mut records = Vec::with_capacity(events.len());
        for event in events {
            records.push(EventRecord::encode_event(event).await?);
        }
        self.apply_records(records).await
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
