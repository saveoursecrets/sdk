//! Event log backed by a database table.
use crate::{
    entity::{
        AccountEntity, AccountRecord, CommitRecord, EventEntity,
        EventRecordRow, FolderEntity, FolderRecord,
    },
    Error,
};
use async_sqlite::{rusqlite::Row, Client};
use async_trait::async_trait;
use binary_stream::futures::{Decodable, Encodable};
use futures::{
    pin_mut,
    stream::{self, BoxStream, StreamExt, TryStreamExt},
};
use sos_core::{
    commit::{CommitHash, CommitProof, CommitTree, Comparison},
    encoding::VERSION1,
    events::{
        patch::{CheckedPatch, Diff, Patch},
        AccountEvent, DeviceEvent, EventLog, EventLogType, EventRecord,
        WriteEvent,
    },
    AccountId, VaultId,
};

#[cfg(feature = "files")]
use sos_core::events::FileEvent;
use tokio_stream::wrappers::ReceiverStream;

/// Event log for changes to an account.
pub type AccountEventLog<E> = DatabaseEventLog<AccountEvent, E>;

/// Event log for devices.
pub type DeviceEventLog<E> = DatabaseEventLog<DeviceEvent, E>;

/// Event log for changes to a folder.
pub type FolderEventLog<E> = DatabaseEventLog<WriteEvent, E>;

/// Event log for changes to external files.
#[cfg(feature = "files")]
pub type FileEventLog<E> = DatabaseEventLog<FileEvent, E>;

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
    account_id: i64,
    folder: Option<FolderRecord>,
    client: Client,
    ids: Vec<i64>,
    log_type: EventLogType,
    tree: CommitTree,
    marker: std::marker::PhantomData<(T, E)>,
}

impl<T, E> DatabaseEventLog<T, E>
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
    /// Create a copy of this event log using a fresh
    /// commit tree and a different client.
    ///
    /// Typically used to create a clone using
    /// a temporary in-memory database.
    pub fn with_new_client(&self, client: Client) -> Self {
        Self {
            account_id: self.account_id,
            folder: self.folder.clone(),
            client,
            ids: Vec::new(),
            log_type: self.log_type,
            tree: CommitTree::new(),
            marker: std::marker::PhantomData,
        }
    }

    async fn lookup_account(
        client: &Client,
        account_id: AccountId,
    ) -> Result<AccountRecord, Error> {
        let account = client
            .conn(move |conn| {
                let account = AccountEntity::new(&conn);
                Ok(account.find_one(&account_id)?)
            })
            .await
            .map_err(Error::from)?;
        Ok(account.try_into()?)
    }

    async fn lookup_folder(
        client: &Client,
        folder_id: VaultId,
    ) -> Result<FolderRecord, Error> {
        let folder = client
            .conn(move |conn| {
                let folder = FolderEntity::new(&conn);
                Ok(folder.find_one(&folder_id)?)
            })
            .await
            .map_err(Error::from)?;
        Ok(FolderRecord::from_row(folder).await?)
    }

    async fn insert_records(
        &mut self,
        records: &[EventRecord],
        delete_before: bool,
    ) -> Result<(), E> {
        let log_type = self.log_type.clone();
        let account_id = self.account_id.clone();
        let folder_id = self.folder.as_ref().map(|f| f.row_id);

        let mut insert_rows = Vec::new();
        let mut commits = Vec::new();
        // let mut last_commit_hash = self.tree().last_commit().clone();
        for record in records {
            commits.push(*record.commit());
            insert_rows.push(EventRecordRow::new(&record)?);
        }

        let id = folder_id.unwrap_or(account_id);

        // Insert into the database.
        let mut ids = self
            .client
            .conn_mut(move |conn| {
                let tx = conn.transaction()?;
                let events = EventEntity::new(&tx);
                if delete_before {
                    events
                        .delete_all_events(log_type, account_id, folder_id)?;
                }
                let ids = events.insert_events(
                    log_type,
                    id,
                    insert_rows.as_slice(),
                )?;
                tx.commit()?;
                Ok(ids)
            })
            .await
            .map_err(Error::from)?;

        if delete_before {
            self.ids = Vec::new();
            self.tree = CommitTree::new();
        }

        // Update the in-memory merkle tree
        let mut hashes =
            commits.iter().map(|c| *c.as_ref()).collect::<Vec<_>>();
        self.tree.append(&mut hashes);
        self.tree.commit();

        // Update row id cache (used for iteration)
        self.ids.append(&mut ids);

        Ok(())
    }
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
    pub async fn new_account(
        client: Client,
        account_id: AccountId,
    ) -> Result<Self, E> {
        let account = Self::lookup_account(&client, account_id).await?;
        Ok(Self {
            account_id: account.row_id,
            folder: None,
            client,
            ids: Vec::new(),
            log_type: EventLogType::Account,
            tree: CommitTree::new(),
            marker: std::marker::PhantomData,
        })
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
    pub async fn new_folder(
        client: Client,
        account_id: AccountId,
        folder_id: VaultId,
    ) -> Result<Self, E> {
        let account = Self::lookup_account(&client, account_id).await?;
        let folder = Self::lookup_folder(&client, folder_id).await?;
        Ok(Self {
            account_id: account.row_id,
            folder: Some(folder),
            client,
            ids: Vec::new(),
            log_type: EventLogType::Folder(folder_id),
            tree: CommitTree::new(),
            marker: std::marker::PhantomData,
        })
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
    pub async fn new_device(
        client: Client,
        account_id: AccountId,
    ) -> Result<Self, E> {
        let account = Self::lookup_account(&client, account_id).await?;
        Ok(Self {
            account_id: account.row_id,
            folder: None,
            client,
            ids: Vec::new(),
            log_type: EventLogType::Device,
            tree: CommitTree::new(),
            marker: std::marker::PhantomData,
        })
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
    pub async fn new_file(
        client: Client,
        account_id: AccountId,
    ) -> Result<Self, Error> {
        let account = Self::lookup_account(&client, account_id).await?;
        Ok(Self {
            account_id: account.row_id,
            folder: None,
            client,
            ids: Vec::new(),
            log_type: EventLogType::Files,
            tree: CommitTree::new(),
            marker: std::marker::PhantomData,
        })
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
    ) -> BoxStream<'async_trait, Result<EventRecord, Self::Error>> {
        let (tx, rx) = tokio::sync::mpsc::channel(8);

        let account_id = self.account_id;
        let folder_id = self.folder.as_ref().map(|f| f.row_id);
        let log_type = self.log_type.clone();
        let client = self.client.clone();

        tokio::spawn(async move {
            client
                .conn_and_then(move |conn| {
                    let id = folder_id.unwrap_or(account_id);
                    let query =
                        EventEntity::find_all_query(log_type, reverse);

                    let mut stmt = conn.prepare_cached(&query.as_string())?;

                    fn convert_row(
                        row: &Row<'_>,
                    ) -> Result<EventRecordRow, crate::Error>
                    {
                        Ok(row.try_into()?)
                    }

                    let rows = stmt.query_and_then([id], |row| {
                        Ok::<_, crate::Error>(convert_row(row)?)
                    })?;

                    for row in rows {
                        let row = row?;
                        let record: EventRecord = row.try_into()?;
                        let sender = tx.clone();
                        futures::executor::block_on(async move {
                            if let Err(err) = sender.send(Ok(record)).await {
                                tracing::error!(error = %err);
                            }
                        });
                    }

                    Ok::<_, Error>(())
                })
                .await?;
            Ok::<_, Error>(())
        });

        ReceiverStream::new(rx).boxed()
    }

    async fn event_stream(
        &self,
        reverse: bool,
    ) -> BoxStream<'async_trait, Result<(EventRecord, T), Self::Error>> {
        let mut ids = self.ids.clone();
        if reverse {
            ids.reverse();
        }
        let items = ids
            .into_iter()
            .map(|id| Ok((self.client.clone(), self.log_type, id)));
        Box::pin(stream::iter(items).try_filter_map(
            |(client, log_type, id)| async move {
                let row = client
                    .conn(move |conn| {
                        let events = EventEntity::new(&conn);
                        Ok(events.find_one(log_type, id)?)
                    })
                    .await
                    .map_err(Error::from)?;
                let record: EventRecord = row.try_into()?;
                let event = record.decode_event::<T>().await?;
                Ok(Some((record, event)))
            },
        ))
    }

    async fn diff_checked(
        &self,
        commit: Option<CommitHash>,
        checkpoint: CommitProof,
    ) -> Result<Diff<T>, Self::Error> {
        let patch = self.diff_events(commit.as_ref()).await?;
        Ok(Diff::<T> {
            last_commit: commit,
            patch,
            checkpoint,
        })
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
        let (records, tree, new_len) = {
            let stream = self.record_stream(true).await;
            pin_mut!(stream);

            let mut records = Vec::new();
            let mut tree = CommitTree::new();
            let mut new_len = 0;

            while let Some(record) = stream.next().await {
                let record = record?;
                if record.commit() == commit {
                    let mut leaves = self.tree().leaves().unwrap_or_default();
                    new_len = leaves.len() - records.len();
                    leaves.truncate(new_len);

                    tree.append(&mut leaves);
                    tree.commit();

                    break;
                }
                records.push(record);
            }

            if new_len == 0 {
                return Err(Error::CommitNotFound(*commit).into());
            }

            (records, tree, new_len)
        };

        let mut ids = self.ids.clone();
        let delete_ids = ids.split_off(new_len);

        // Delete from the database
        let log_type = self.log_type.clone();
        self.client
            .conn_mut(move |conn| {
                let tx = conn.transaction()?;
                let events = EventEntity::new(&tx);
                for id in delete_ids {
                    events.delete_one(log_type, id)?;
                }
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(Error::from)?;

        // Update identifier cache
        ids.truncate(new_len);
        self.ids = ids;

        // Update merkle tree
        self.tree = tree;

        Ok(records)
    }

    async fn load_tree(&mut self) -> Result<(), Self::Error> {
        let log_type = self.log_type.clone();
        let account_id = self.account_id.clone();
        let folder_id = self.folder.as_ref().map(|f| f.row_id);
        let commits = self
            .client
            .conn_and_then(move |conn| {
                let events = EventEntity::new(&conn);
                let commits =
                    events.load_commits(log_type, account_id, folder_id)?;
                Ok::<_, Error>(commits)
            })
            .await?;
        for commit in commits {
            let record: CommitRecord = commit.try_into()?;
            self.ids.push(record.row_id);
            self.tree.insert(*record.commit_hash.as_ref());
        }
        self.tree.commit();
        Ok(())
    }

    async fn clear(&mut self) -> Result<(), Self::Error> {
        let log_type = self.log_type.clone();
        let account_id = self.account_id.clone();
        let folder_id = self.folder.as_ref().map(|f| f.row_id);
        self.client
            .conn_mut(move |conn| {
                let tx = conn.transaction()?;
                let events = EventEntity::new(&tx);
                events.delete_all_events(log_type, account_id, folder_id)?;
                tx.commit()?;
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
        self.insert_records(records.as_slice(), false).await
    }

    async fn patch_checked(
        &mut self,
        commit_proof: &CommitProof,
        patch: &Patch<T>,
    ) -> Result<CheckedPatch, Self::Error> {
        let comparison = self.tree().compare(commit_proof)?;
        match comparison {
            Comparison::Equal => {
                self.patch_unchecked(patch).await?;
                let proof = self.tree().head()?;
                Ok(CheckedPatch::Success(proof))
            }
            Comparison::Contains(indices) => {
                let head = self.tree().head()?;
                let contains = self.tree().proof(&indices)?;
                Ok(CheckedPatch::Conflict {
                    head,
                    contains: Some(contains),
                })
            }
            Comparison::Unknown => {
                let head = self.tree().head()?;
                Ok(CheckedPatch::Conflict {
                    head,
                    contains: None,
                })
            }
        }
    }

    async fn replace_all_events(
        &mut self,
        diff: &Diff<T>,
    ) -> Result<(), Self::Error> {
        self.insert_records(diff.patch.records(), true).await?;

        let computed = self.tree().head()?;
        let verified = computed == diff.checkpoint;
        if !verified {
            return Err(Error::CheckpointVerification {
                checkpoint: diff.checkpoint.root,
                computed: computed.root,
            }
            .into());
        }

        Ok(())
    }

    async fn patch_unchecked(
        &mut self,
        patch: &Patch<T>,
    ) -> Result<(), Self::Error> {
        self.apply_records(patch.records().to_vec()).await
    }

    async fn diff_records(
        &self,
        commit: Option<&CommitHash>,
    ) -> Result<Vec<EventRecord>, Self::Error> {
        let mut events = Vec::new();

        let stream = self.record_stream(true).await;
        pin_mut!(stream);

        while let Some(record) = stream.next().await {
            let record = record?;
            if let Some(commit) = commit {
                if record.commit() == commit {
                    return Ok(events);
                }
            }
            // Iterating in reverse order as we would typically
            // be looking for commits near the end of the event log
            // but we want the patch events in the order they were
            // appended so insert at the beginning to reverse the list
            events.insert(0, record);
        }

        // If the caller wanted to patch until a particular commit
        // but it doesn't exist we error otherwise we would return
        // all the events
        if let Some(commit) = commit {
            return Err(Error::CommitNotFound(*commit).into());
        }

        Ok(events)
    }

    fn version(&self) -> u16 {
        self.folder
            .as_ref()
            .map(|f| *f.summary.version())
            .unwrap_or(VERSION1)
    }
}
