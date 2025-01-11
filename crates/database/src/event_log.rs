//! Event log backed by a database table.
use crate::{
    db::{
        AccountEntity, AccountRecord, CommitRecord, EventEntity, EventTable,
        FolderEntity, FolderRecord,
    },
    Error,
};
use async_sqlite::Client;
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
        AccountEvent, DeviceEvent, EventLog, EventRecord, WriteEvent,
    },
    AccountId, VaultId,
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
    account_id: i64,
    folder: Option<FolderRecord>,
    client: Client,
    ids: Vec<i64>,
    table: EventTable,
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
        Ok(folder.try_into()?)
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
            table: EventTable::AccountEvents,
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
            table: EventTable::FolderEvents,
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
            table: EventTable::DeviceEvents,
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
            table: EventTable::FileEvents,
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
        let mut ids = self.ids.clone();
        if reverse {
            ids.reverse();
        }
        let items = ids
            .into_iter()
            .map(|id| Ok((self.client.clone(), self.table, id)));
        Box::pin(stream::iter(items).try_filter_map(
            |(client, table, id)| async move {
                let row = client
                    .conn(move |conn| {
                        let events = EventEntity::new(&conn);
                        Ok(events.find_one(table, id)?)
                    })
                    .await
                    .map_err(Error::from)?;
                Ok(Some(row.try_into()?))
            },
        ))
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
            .map(|id| Ok((self.client.clone(), self.table, id)));
        Box::pin(stream::iter(items).try_filter_map(
            |(client, table, id)| async move {
                let row = client
                    .conn(move |conn| {
                        let events = EventEntity::new(&conn);
                        Ok(events.find_one(table, id)?)
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
        let table = self.table.clone();
        self.client
            .conn_mut(move |conn| {
                let tx = conn.transaction()?;
                let events = EventEntity::new(&tx);
                for id in delete_ids {
                    events.delete_one(table, id)?;
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
        let table = self.table.clone();
        let account_id = self.account_id.clone();
        let folder_id = self.folder.as_ref().map(|f| f.row_id);
        let commits = self
            .client
            .conn(move |conn| {
                let events = EventEntity::new(&conn);
                let commits =
                    events.load_commits(table, account_id, folder_id)?;
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
        let table = self.table.clone();
        let account_id = self.account_id.clone();
        let folder_id = self.folder.as_ref().map(|f| f.row_id);
        self.client
            .conn(move |conn| {
                let events = EventEntity::new(&conn);
                events.delete_all_events(table, account_id, folder_id)?;
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
        let table = self.table.clone();
        let account_id = self.account_id.clone();

        let mut insert_rows = Vec::new();
        let mut commits = Vec::new();
        let mut last_commit_hash = self.tree().last_commit();
        for mut record in records {
            record.set_last_commit(last_commit_hash);
            commits.push(*record.commit());
            last_commit_hash = Some(*record.commit());
            insert_rows.push((record.time().to_rfc3339()?, record));
        }

        // Insert into the database.
        let mut ids = self
            .client
            .conn(move |conn| {
                let events = EventEntity::new(&conn);
                let ids =
                    events.insert_events(table, account_id, insert_rows)?;
                Ok(ids)
            })
            .await
            .map_err(Error::from)?;

        // Update the in-memory merkle tree
        let mut hashes =
            commits.iter().map(|c| *c.as_ref()).collect::<Vec<_>>();
        self.tree.append(&mut hashes);
        self.tree.commit();

        // Update row id cache (used for iteration)
        self.ids.append(&mut ids);

        Ok(())
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
