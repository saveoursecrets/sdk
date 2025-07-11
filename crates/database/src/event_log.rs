//! Event log backed by a database table.
//!
//! Event logs can belong to an account or to a folder
//! so we keep track of the owner of the event log for
//! database queries.
//!
//! If you were to move a folder between accounts or otherwise
//! re-owner an event log you must create a new event log so
//! the owner reference is updated.
use crate::{
    entity::{
        AccountEntity, CommitRecord, EventEntity, EventRecordRow,
        FolderEntity, FolderRecord,
    },
    Error,
};
use async_sqlite::{rusqlite::Row, Client};
use async_trait::async_trait;
use binary_stream::futures::{Decodable, Encodable};
use futures::{
    pin_mut,
    stream::{BoxStream, StreamExt, TryStreamExt},
};
use sos_core::{
    commit::{CommitHash, CommitProof, CommitSpan, CommitTree, Comparison},
    encoding::VERSION1,
    events::{
        changes_feed,
        patch::{CheckedPatch, Diff, Patch},
        AccountEvent, DeviceEvent, EventLog, EventLogType, EventRecord,
        LocalChangeEvent, WriteEvent,
    },
    AccountId, VaultId,
};

/// Owner of an event log.
#[derive(Clone)]
#[doc(hidden)]
pub enum EventLogOwner {
    /// Event log owned by an account.
    Account(AccountId, i64),
    /// Event log owned by a folder.
    Folder(AccountId, FolderRecord),
}

impl EventLogOwner {
    /// Account idenifier.
    pub fn account_id(&self) -> &AccountId {
        match self {
            EventLogOwner::Account(account_id, _) => account_id,
            EventLogOwner::Folder(account_id, _) => account_id,
        }
    }
}

impl From<&EventLogOwner> for i64 {
    fn from(value: &EventLogOwner) -> Self {
        match value {
            EventLogOwner::Account(_, id) => *id,
            EventLogOwner::Folder(_, folder) => folder.row_id,
        }
    }
}

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
    owner: EventLogOwner,
    client: Client,
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
    pub fn with_new_client(
        &self,
        client: Client,
        owner: Option<EventLogOwner>,
    ) -> Self {
        Self {
            owner: owner.unwrap_or_else(|| self.owner.clone()),
            client,
            log_type: self.log_type,
            tree: CommitTree::new(),
            marker: std::marker::PhantomData,
        }
    }

    /// Lookup an owner for the event log.
    async fn lookup_owner(
        client: &Client,
        account_id: &AccountId,
        log_type: &EventLogType,
    ) -> Result<EventLogOwner, Error> {
        let account_id = *account_id;
        let log_type = *log_type;
        let result = client
            .conn_and_then(move |conn| {
                let account = AccountEntity::new(&conn);
                let account_row = account.find_one(&account_id)?;
                match log_type {
                    EventLogType::Folder(folder_id) => {
                        let folder = FolderEntity::new(&conn);
                        let folder_row = folder.find_one(&folder_id)?;
                        Ok::<_, Error>((account_row, Some(folder_row)))
                    }
                    _ => Ok::<_, Error>((account_row, None)),
                }
            })
            .await?;

        Ok(match result {
            (account_row, None) => {
                EventLogOwner::Account(account_id, account_row.row_id)
            }
            (_, Some(folder_row)) => EventLogOwner::Folder(
                account_id,
                FolderRecord::from_row(folder_row).await?,
            ),
        })
    }

    async fn insert_records(
        &mut self,
        records: &[EventRecord],
        delete_before: bool,
    ) -> Result<(), E> {
        if records.is_empty() {
            return Ok(());
        }

        let mut span = CommitSpan {
            before: self.tree.last_commit(),
            after: None,
        };

        let log_type = self.log_type.clone();
        let mut insert_rows = Vec::new();
        let mut commits = Vec::new();
        for record in records {
            commits.push(*record.commit());
            insert_rows.push(EventRecordRow::new(&record)?);
        }

        let id = (&self.owner).into();

        // Insert into the database.
        self.client
            .conn_mut(move |conn| {
                let tx = conn.transaction()?;
                let events = EventEntity::new(&tx);
                if delete_before {
                    events.delete_all_events(log_type, id)?;
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
            self.tree = CommitTree::new();
        }

        // Update the in-memory merkle tree
        let mut hashes =
            commits.iter().map(|c| *c.as_ref()).collect::<Vec<_>>();
        self.tree.append(&mut hashes);
        self.tree.commit();

        span.after = self.tree.last_commit();

        changes_feed().send_replace(LocalChangeEvent::AccountModified {
            account_id: *self.owner.account_id(),
            log_type: self.log_type,
            commit_span: span,
        });

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
        let log_type = EventLogType::Account;
        let owner =
            Self::lookup_owner(&client, &account_id, &log_type).await?;
        Ok(Self {
            owner,
            client,
            log_type,
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
        let log_type = EventLogType::Folder(folder_id);
        let owner =
            Self::lookup_owner(&client, &account_id, &log_type).await?;

        Ok(Self {
            owner,
            client,
            log_type,
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
        let log_type = EventLogType::Device;
        let owner =
            Self::lookup_owner(&client, &account_id, &log_type).await?;
        Ok(Self {
            owner,
            client,
            log_type,
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
        let log_type = EventLogType::Files;
        let owner =
            Self::lookup_owner(&client, &account_id, &log_type).await?;
        Ok(Self {
            owner,
            client,
            log_type,
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

        let id: i64 = (&self.owner).into();
        let log_type = self.log_type.clone();
        let client = self.client.clone();

        tokio::spawn(async move {
            client
                .conn_and_then(move |conn| {
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
                        if tx.is_closed() {
                            break;
                        }
                        let row = row?;
                        let record: EventRecord = row.try_into()?;
                        let inner_tx = tx.clone();
                        let res = futures::executor::block_on(async move {
                            inner_tx.send(Ok(record)).await
                        });
                        if let Err(e) = res {
                            tracing::error!(error = %e);
                            break;
                        }
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
        self.record_stream(reverse)
            .await
            .try_filter_map(|record| async {
                let event = record.decode_event::<T>().await?;
                Ok(Some((record, event)))
            })
            .boxed()
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
        let (records, tree) = {
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

            (records, tree)
        };

        let delete_ids =
            records.iter().map(|r| *r.commit()).collect::<Vec<_>>();

        // Delete from the database
        let log_type = self.log_type.clone();
        self.client
            .conn_mut(move |conn| {
                let tx = conn.transaction()?;
                let events = EventEntity::new(&tx);
                for id in delete_ids {
                    events.delete_one(log_type, &id)?;
                }
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(Error::from)?;

        // Update merkle tree
        self.tree = tree;

        Ok(records)
    }

    async fn load_tree(&mut self) -> Result<(), Self::Error> {
        let log_type = self.log_type.clone();
        let id = (&self.owner).into();
        let commits = self
            .client
            .conn_and_then(move |conn| {
                let events = EventEntity::new(&conn);
                let commits = events.load_commits(log_type, id)?;
                Ok::<_, Error>(commits)
            })
            .await?;
        let mut tree = CommitTree::new();
        for commit in commits {
            let record: CommitRecord = commit.try_into()?;
            tree.insert(*record.commit_hash.as_ref());
        }
        tree.commit();
        self.tree = tree;
        Ok(())
    }

    async fn clear(&mut self) -> Result<(), Self::Error> {
        let log_type = self.log_type.clone();
        let id = (&self.owner).into();
        self.client
            .conn_mut(move |conn| {
                let tx = conn.transaction()?;
                let events = EventEntity::new(&tx);
                events.delete_all_events(log_type, id)?;
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(Error::from)?;
        self.tree = CommitTree::new();
        Ok(())
    }

    async fn apply(&mut self, events: &[T]) -> Result<(), Self::Error> {
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
        match &self.owner {
            EventLogOwner::Folder(_, folder) => *folder.summary.version(),
            EventLogOwner::Account(_, _) => VERSION1,
        }
    }
}
