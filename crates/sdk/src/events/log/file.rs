//! Event log file.
//!
//! Event logs consist of 4 identity bytes followed by one or more
//! rows of log records; each row contains the row length prepended
//! and appended so that rows can be efficiently iterated in
//! both directions.
//!
//! Row components with byte sizes:
//!
//! ```text
//! | 4 row length | 12 timestamp | 32 last commit hash | 32 commit hash | 4 data length | data | 4 row length |
//! ```
//!
//! The first row must always contain a last commit hash that is all zero.
//!
use crate::{
    commit::{CommitHash, CommitProof, CommitTree, Comparison},
    encode,
    encoding::{encoding_options, VERSION1},
    events::{AccountEvent, IntoRecord, WriteEvent},
    formats::{
        stream::{MemoryBuffer, MemoryInner},
        EventLogRecord, FileIdentity, FileItem, FormatStream,
        FormatStreamIterator,
    },
    vfs::{self, File, OpenOptions},
    Error, Result,
};

use async_stream::try_stream;
use futures::stream::BoxStream;

use futures::io::{
    AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite,
    AsyncWriteExt, BufReader, Cursor,
};

use crate::events::DeviceEvent;

#[cfg(feature = "files")]
use crate::events::FileEvent;

use super::patch::{CheckedPatch, Diff, Patch};

use async_trait::async_trait;
use std::{
    io::SeekFrom,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::sync::{Mutex, MutexGuard};
use tokio_util::compat::Compat;
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

use binary_stream::futures::{BinaryReader, Decodable, Encodable};
use tempfile::NamedTempFile;

use super::{EventRecord, FolderReducer};

/// Type for logging events to a file.
pub type DiscLog = Compat<File>;

/// Associated data when writing event logs to disc.
pub type DiscData = PathBuf;

/// Type for logging events to memory.
pub type MemoryLog = MemoryBuffer;

/// Associated data when writing event logs to memory.
pub type MemoryData = MemoryInner;

/// Event log that writes to disc.
pub type DiscEventLog<E> = EventLog<E, DiscLog, DiscLog, PathBuf>;

/// Event log that writes to memory.
pub type MemoryEventLog<E> =
    EventLog<E, MemoryBuffer, MemoryBuffer, MemoryInner>;

/// Event log for changes to a folder that writes to memory.
pub type MemoryFolderLog =
    EventLog<WriteEvent, MemoryBuffer, MemoryBuffer, MemoryInner>;

/// Event log for changes to an account.
pub type AccountEventLog = DiscEventLog<AccountEvent>;

/// Event log for devices.
pub type DeviceEventLog = DiscEventLog<DeviceEvent>;

/// Event log for changes to a folder.
pub type FolderEventLog = DiscEventLog<WriteEvent>;

/// Event log for changes to external files.
#[cfg(feature = "files")]
pub type FileEventLog = DiscEventLog<FileEvent>;

/// Type of an event log file iterator.
type Iter = Box<dyn FormatStreamIterator<EventLogRecord> + Send + Sync>;

/// Read the bytes for the encoded event
/// inside the log record.
async fn read_event_buffer<R, W>(
    handle: Arc<Mutex<(R, W)>>,
    record: &EventLogRecord,
) -> Result<Vec<u8>>
where
    R: AsyncRead + AsyncSeek + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let mut file = MutexGuard::map(handle.lock().await, |f| &mut f.0);

    let offset = record.value();
    let row_len = offset.end - offset.start;

    file.seek(SeekFrom::Start(offset.start)).await?;

    let mut buf = vec![0u8; row_len as usize];
    file.read_exact(&mut buf).await?;

    Ok(buf)
}

/// Event log iterator, stream and diff support.
#[async_trait]
pub trait EventLogExt<E, R, W, D>: Send + Sync
where
    E: Default + Encodable + Decodable + Send + Sync + 'static,
    R: AsyncRead + AsyncSeek + Unpin + Send + Sync + 'static,
    W: AsyncWrite + AsyncSeek + Unpin + Send + Sync + 'static,
    D: Clone,
{
    /// Commit tree contains the in-memory merkle tree.
    fn tree(&self) -> &CommitTree;

    /// Mutable commit tree.
    #[doc(hidden)]
    fn tree_mut(&mut self) -> &mut CommitTree;

    /// File reader and writer.
    #[doc(hidden)]
    fn file(&self) -> Arc<Mutex<(R, W)>>;

    /// Identity bytes.
    #[doc(hidden)]
    fn identity(&self) -> &'static [u8];

    /// Encoding version.
    #[doc(hidden)]
    fn version(&self) -> Option<u16>;

    /// Associated data.
    #[doc(hidden)]
    fn data(&self) -> D;

    #[doc(hidden)]
    fn data_any(&self) -> &dyn std::any::Any;

    /// Length of the file magic bytes and optional
    /// encoding version.
    #[doc(hidden)]
    fn header_len(&self) -> usize {
        let mut len = self.identity().len();
        if self.version().is_some() {
            len += (u16::BITS / 8) as usize;
        }
        len
    }

    /// Event log iterator.
    async fn iter(&self, reverse: bool) -> Result<Iter>;

    /// Load data from storage to build a commit tree in memory.
    async fn load_tree(&mut self) -> Result<()> {
        let mut commits = Vec::new();

        let mut it = self.iter(false).await?;
        while let Some(record) = it.next().await? {
            commits.push(record.commit());
        }

        let tree = self.tree_mut();
        *tree = CommitTree::new();
        tree.append(&mut commits);
        tree.commit();
        Ok(())
    }

    /// Stream of event records and decoded events.
    ///
    /// # Panics
    ///
    /// If the file iterator cannot read the event log file.
    async fn stream(
        &self,
        reverse: bool,
    ) -> BoxStream<'static, Result<(EventRecord, E)>> {
        let mut it = self
            .iter(reverse)
            .await
            .expect("failed to initialize stream");

        let handle = self.file();
        Box::pin(try_stream! {
            while let Some(record) = it.next().await? {
                let event_buffer = read_event_buffer(
                    handle.clone(), &record).await?;

                let event_record: EventRecord = (record, event_buffer).into();

                let event = event_record.decode_event::<E>().await?;
                yield (event_record, event);
            }
        })
    }

    /// Create a checked diff from a commit.
    ///
    /// Used when merging to verify that the HEAD of the
    /// event log matches the checkpoint before applying
    /// the patch.
    async fn diff_checked(
        &self,
        commit: Option<CommitHash>,
        checkpoint: CommitProof,
    ) -> Result<Diff<E>> {
        let patch = self.diff_events(commit.as_ref()).await?;
        Ok(Diff::<E> {
            last_commit: commit,
            patch,
            checkpoint,
        })
    }

    /// Create an unchecked diff of all events.
    ///
    /// Used during a force merge to overwrite an event log
    /// with new events.
    ///
    /// For example, when destructive changes are made (change
    /// cipher or password) then other devices need to rewrite
    /// the event logs.
    async fn diff_unchecked(&self) -> Result<Diff<E>> {
        let patch = self.diff_events(None).await?;
        Ok(Diff::<E> {
            last_commit: None,
            patch,
            checkpoint: self.tree().head()?,
        })
    }

    /// Diff of events until a specific commit; does
    /// not include the target commit.
    ///
    /// If no commit hash is given then all events are included.
    async fn diff_events(
        &self,
        commit: Option<&CommitHash>,
    ) -> Result<Patch<E>> {
        let records = self.diff_records(commit).await?;
        Ok(Patch::new(records))
    }

    /// Diff of event records until a specific commit.
    ///
    /// Searches backwards until it finds the specified commit
    /// if given; if no commit is given the diff will include
    /// all event records.
    ///
    /// Does not include the target commit.
    async fn diff_records(
        &self,
        commit: Option<&CommitHash>,
    ) -> Result<Vec<EventRecord>> {
        let mut events = Vec::new();
        let file = self.file();
        let mut it = self.iter(true).await?;
        while let Some(record) = it.next().await? {
            if let Some(commit) = commit {
                if &record.commit() == commit.as_ref() {
                    return Ok(events);
                }
            }
            let buffer =
                read_event_buffer(Arc::clone(&file), &record).await?;
            // Iterating in reverse order as we would typically
            // be looking for commits near the end of the event log
            // but we want the patch events in the order they were
            // appended so insert at the beginning to reverse the list
            events.insert(0, (record, buffer).into());
        }

        // If the caller wanted to patch until a particular commit
        // but it doesn't exist we error otherwise we would return
        // all the events
        if let Some(commit) = commit {
            return Err(Error::CommitNotFound(*commit));
        }

        Ok(events)
    }

    /// Rewind this event log discarding commits after
    /// the specific commit.
    ///
    /// Returns the collection of log records that can
    /// be used to revert if a subsequent merge fails.
    async fn rewind(
        &mut self,
        commit: &CommitHash,
    ) -> Result<Vec<EventRecord>>;

    /// Delete all events from the log file on disc
    /// and in-memory.
    async fn clear(&mut self) -> Result<()> {
        self.truncate().await?;
        let tree = self.tree_mut();
        *tree = CommitTree::new();
        Ok(())
    }

    /// Truncate the backing storage to an empty file.
    async fn truncate(&mut self) -> Result<()>;

    /// Read encoding version from the backing storage.
    #[doc(hidden)]
    async fn read_file_version(&self) -> Result<u16> {
        if self.version().is_some() {
            let rw = self.file();
            let mut file = MutexGuard::map(rw.lock().await, |f| &mut f.0);
            file.seek(SeekFrom::Start(self.identity().len() as u64))
                .await?;
            let mut buf = [0; 2];
            file.read_exact(&mut buf).await?;
            let version_bytes: [u8; 2] = buf.as_slice().try_into()?;
            let version = u16::from_le_bytes(version_bytes);
            Ok(version)
        // Backwards compatible with formats without
        // version information, just return the default version
        } else {
            Ok(VERSION1)
        }
    }

    /// Append a patch to this event log only if the
    /// head of the tree matches the given proof.
    async fn patch_checked(
        &mut self,
        commit_proof: &CommitProof,
        patch: &Patch<E>,
    ) -> Result<CheckedPatch> {
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

    /// Replace all events in this event log with the events in the diff.
    ///
    /// For disc based implementations a snapshot is created
    /// of the event log file beforehand by copying the event
    /// log to a new file with a `snapshot-{root_hash}` file extension.
    ///
    /// The events on disc and the in-memory merkle tree are then
    /// removed before applying the patch in the diff.
    ///
    /// After applying the events if the HEAD of the event log
    /// does not match the `checkpoint` in the diff verification
    /// fails and an attempt is made to rollback to the snapshot.
    ///
    /// When verification fails an [Error::CheckpointVerification]
    /// error will always be returned.
    async fn patch_replace(&mut self, diff: &Diff<E>) -> Result<()> {
        // Create a snapshot for disc-based implementations
        let snapshot = self.try_create_snapshot().await?;

        // Erase the file content and in-memory merkle tree
        self.clear().await?;

        // Apply the new events
        self.patch_unchecked(&diff.patch).await?;

        // Verify against the checkpoint
        let computed = self.tree().head()?;
        let verified = computed == diff.checkpoint;

        let mut rollback_completed = false;
        match (verified, &snapshot) {
            // Try to rollback if verification failed
            (false, Some(snapshot_path)) => {
                rollback_completed =
                    self.try_rollback_snapshot(snapshot_path).await.is_ok();
            }
            // Delete the snapshot if verified
            (true, Some(snapshot_path)) => {
                vfs::remove_file(snapshot_path).await?;
            }
            _ => {}
        }

        if verified {
            Ok(())
        } else {
            Err(Error::CheckpointVerification {
                checkpoint: diff.checkpoint.root,
                computed: computed.root,
                snapshot,
                rollback_completed,
            })
        }
    }

    #[doc(hidden)]
    async fn try_create_snapshot(&self) -> Result<Option<PathBuf>> {
        if let Some(source_path) = self.data_any().downcast_ref::<PathBuf>() {
            let file = self.file();
            let _guard = file.lock().await;

            if let Some(root) = self.tree().root() {
                let mut snapshot_path = source_path.clone();
                snapshot_path.set_extension(&format!("snapshot-{}", root));

                let metadata = vfs::metadata(&source_path).await?;
                tracing::debug!(
                    num_events = %self.tree().len(),
                    file_size = %metadata.len(),
                    source = %source_path.display(),
                    snapshot = %snapshot_path.display(),
                    "event_log::snapshot::create"
                );

                vfs::copy(&source_path, &snapshot_path).await?;
                Ok(Some(snapshot_path))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    #[doc(hidden)]
    async fn try_rollback_snapshot(
        &mut self,
        snapshot_path: &PathBuf,
    ) -> Result<()> {
        if let Some(source_path) = self.data_any().downcast_ref::<PathBuf>() {
            let file = self.file();
            let _guard = file.lock().await;

            let metadata = vfs::metadata(snapshot_path).await?;
            tracing::debug!(
                file_size = %metadata.len(),
                source = %source_path.display(),
                snapshot = %snapshot_path.display(),
                "event_log::snapshot::rollback"
            );

            vfs::remove_file(&source_path).await?;
            vfs::rename(snapshot_path, &source_path).await?;
            self.load_tree().await?;

            Ok(())
        } else {
            Ok(())
        }
    }

    /// Append a patch to this event log.
    async fn patch_unchecked(&mut self, patch: &Patch<E>) -> Result<()> {
        /*
        if let Some(record) = patch.records().first() {
            self.check_event_time_ahead(record).await?;
        }
        */
        self.apply_records(patch.records().to_vec()).await
    }

    /// Find the last log record using a reverse iterator.
    async fn head_record(&self) -> Result<Option<EventLogRecord>> {
        let mut it = self.iter(true).await?;
        it.next().await
    }

    /*
    #[doc(hidden)]
    async fn check_event_time_ahead(
        &self,
        record: &EventRecord,
    ) -> Result<()> {
        if let Some(head_record) = self.head_record().await? {
            if record.time().0 < head_record.time().0 {
                println!("record: {:#?}", record.time().0);
                println!("head: {:#?}", head_record.time().0);
                return Err(Error::EventTimeBehind);
            }
        }
        Ok(())
    }
    */

    /// Append a collection of events and commit the tree hashes
    /// only if all the events were successfully written.
    async fn apply(&mut self, events: Vec<&E>) -> Result<()> {
        let mut records = Vec::with_capacity(events.len());
        for event in events {
            records.push(event.default_record().await?);
        }
        self.apply_records(records).await
    }

    /// Append raw event records to the event log.
    ///
    /// Use this to preserve the time information in
    /// existing event records.
    async fn apply_records(
        &mut self,
        records: Vec<EventRecord>,
    ) -> Result<()> {
        let mut buffer: Vec<u8> = Vec::new();
        let mut commits = Vec::new();
        let mut last_commit_hash = self.tree().last_commit();

        for mut record in records {
            record.set_last_commit(last_commit_hash);
            let mut buf = encode(&record).await?;
            buffer.append(&mut buf);
            last_commit_hash = Some(*record.commit());
            commits.push(*record.commit());
        }

        // File based implementations should attempt to
        // acquire an advisory lock
        if let Some(path) = self.data_any().downcast_ref::<PathBuf>() {
            use tokio::io::AsyncWriteExt as TokioAsyncWriteExt;

            let rw = self.file();
            let _lock = rw.lock().await;

            let file = OpenOptions::new()
                .write(true)
                .append(true)
                .open(path)
                .await?;

            let mut guard = vfs::lock_write(file).await?;

            #[cfg(target_arch = "wasm32")]
            {
                file.seek(SeekFrom::End(0)).await?;
            }
            match guard.write_all(&buffer).await {
                Ok(_) => {
                    guard.flush().await?;
                    let mut hashes = commits
                        .iter()
                        .map(|c| *c.as_ref())
                        .collect::<Vec<_>>();
                    let tree = self.tree_mut();
                    tree.append(&mut hashes);
                    tree.commit();
                    Ok(())
                }
                Err(e) => Err(e.into()),
            }
        // In-memory implementations can just write
        // without acquiring an advisory lock
        } else {
            let rw = self.file();
            let mut file = MutexGuard::map(rw.lock().await, |f| &mut f.1);
            // Workaround for bug in the vfs implementation on wasm32
            // that is overwriting the file identity bytes when
            // applying records.
            #[cfg(target_arch = "wasm32")]
            {
                file.seek(SeekFrom::End(0)).await?;
            }
            match file.write_all(&buffer).await {
                Ok(_) => {
                    file.flush().await?;
                    let mut hashes = commits
                        .iter()
                        .map(|c| *c.as_ref())
                        .collect::<Vec<_>>();
                    let tree = self.tree_mut();
                    tree.append(&mut hashes);
                    tree.commit();
                    Ok(())
                }
                Err(e) => Err(e.into()),
            }
        }
    }

    /// Read the event data from an item.
    #[doc(hidden)]
    async fn decode_event(&self, item: &EventLogRecord) -> Result<E> {
        let value = item.value();

        let rw = self.file();
        let mut file = MutexGuard::map(rw.lock().await, |f| &mut f.0);

        file.seek(SeekFrom::Start(value.start)).await?;
        let mut buffer = vec![0; (value.end - value.start) as usize];
        file.read_exact(buffer.as_mut_slice()).await?;

        let mut stream = BufReader::new(Cursor::new(&mut buffer));
        let mut reader = BinaryReader::new(&mut stream, encoding_options());
        let mut event: E = Default::default();
        event.decode(&mut reader).await?;
        Ok(event)
    }
}

/// Event log.
///
/// Appends events to an append-only writer and reads events
/// via a reader whilst managing an in-memory merkle tree
/// of event hashes.
pub struct EventLog<E, R, W, D>
where
    E: Default + Encodable + Decodable + Send + Sync,
    R: AsyncRead + AsyncSeek + Unpin + Send + Sync,
    W: AsyncWrite + Unpin + Send + Sync,
    D: Clone,
{
    file: Arc<Mutex<(R, W)>>,
    tree: CommitTree,
    data: D,
    identity: &'static [u8],
    version: Option<u16>,
    phantom: std::marker::PhantomData<(E, D)>,
}

#[async_trait]
impl<E> EventLogExt<E, DiscLog, DiscLog, PathBuf>
    for EventLog<E, DiscLog, DiscLog, PathBuf>
where
    E: Default + Encodable + Decodable + Send + Sync + 'static,
{
    async fn iter(&self, reverse: bool) -> Result<Iter> {
        let content_offset = self.header_len() as u64;
        let read_stream = File::open(self.data()).await?.compat();
        let it: Iter = Box::new(
            FormatStream::<EventLogRecord, Compat<File>>::new_file(
                read_stream,
                self.identity,
                true,
                Some(content_offset),
                reverse,
            )
            .await?,
        );
        Ok(it)
    }

    fn tree(&self) -> &CommitTree {
        &self.tree
    }

    fn tree_mut(&mut self) -> &mut CommitTree {
        &mut self.tree
    }

    fn identity(&self) -> &'static [u8] {
        self.identity
    }

    fn version(&self) -> Option<u16> {
        self.version
    }

    fn file(&self) -> Arc<Mutex<(DiscLog, DiscLog)>> {
        Arc::clone(&self.file)
    }

    fn data(&self) -> PathBuf {
        self.data.clone()
    }

    fn data_any(&self) -> &dyn std::any::Any {
        &self.data
    }

    async fn truncate(&mut self) -> Result<()> {
        use tokio::io::{
            AsyncSeekExt as TokioAsyncSeekExt,
            AsyncWriteExt as TokioAsyncWriteExt,
        };
        let _ = self.file.lock().await;

        // Workaround for set_len(0) failing with "Access Denied" on Windows
        // SEE: https://github.com/rust-lang/rust/issues/105437
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.data)
            .await?;

        file.seek(SeekFrom::Start(0)).await?;

        let mut guard = vfs::lock_write(file).await?;
        guard.write_all(self.identity).await?;
        if let Some(version) = self.version() {
            guard.write_all(&version.to_le_bytes()).await?;
        }
        guard.flush().await?;

        Ok(())
    }

    async fn rewind(
        &mut self,
        commit: &CommitHash,
    ) -> Result<Vec<EventRecord>> {
        let mut length = vfs::metadata(&self.data).await?.len();
        // Iterate backwards and track how many commits are pruned
        let mut it = self.iter(true).await?;

        tracing::trace!(length = %length, "event_log::rewind");

        let handle = self.file();
        let mut records = Vec::new();

        while let Some(record) = it.next().await? {
            // Found the target commit
            if &record.commit() == commit.as_ref() {
                // Acquire file lock as we will truncate
                let file = self.file();
                let _guard = file.lock().await;

                // Rewrite the in-memory tree
                let mut leaves = self.tree().leaves().unwrap_or_default();
                if leaves.len() > records.len() {
                    let new_len = leaves.len() - records.len();
                    leaves.truncate(new_len);
                    let mut tree = CommitTree::new();
                    tree.append(&mut leaves);
                    tree.commit();
                    *self.tree_mut() = tree;
                } else {
                    return Err(Error::RewindLeavesLength);
                }

                // Truncate the file to the new length
                let file =
                    OpenOptions::new().write(true).open(&self.data).await?;
                file.set_len(length).await?;

                /*
                let mut guard = vfs::lock_write(file).await?;
                guard.inner_mut().set_len(length).await?;
                */

                return Ok(records);
            }

            // Compute new length and number of pruned commits
            let byte_length = record.byte_length();

            if byte_length < length {
                length -= byte_length;
            }

            let event_buffer =
                read_event_buffer(handle.clone(), &record).await?;
            let event_record: EventRecord = (record, event_buffer).into();
            records.push(event_record);

            tracing::trace!(
                length = %length,
                byte_length = %byte_length,
                num_pruned = %records.len(),
                "event_log::rewind",
            );
        }

        Err(Error::CommitNotFound(*commit))
    }
}

impl<E> EventLog<E, DiscLog, DiscLog, PathBuf>
where
    E: Default + Encodable + Decodable + Send + Sync,
{
    /// Create the writer for an event log file.
    async fn create_writer<P: AsRef<Path>>(
        path: P,
        identity: &'static [u8],
        encoding_version: Option<u16>,
    ) -> Result<DiscLog> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())
            .await?;

        let size = vfs::metadata(path.as_ref()).await?.len();
        if size == 0 {
            use tokio::io::AsyncWriteExt as TokioAsyncWriteExt;
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path.as_ref())
                .await?;
            let mut guard = vfs::lock_write(file).await?;
            let mut header = identity.to_vec();
            if let Some(version) = encoding_version {
                header.extend_from_slice(&version.to_le_bytes());
            }
            guard.write_all(&header).await?;
            guard.flush().await?;
        }

        Ok(file.compat_write())
    }

    /// Create the reader for an event log file.
    async fn create_reader<P: AsRef<Path>>(path: P) -> Result<DiscLog> {
        Ok(File::open(path).await?.compat())
    }
}

impl EventLog<WriteEvent, DiscLog, DiscLog, PathBuf> {
    /// Create a new folder event log file.
    pub async fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        use crate::constants::FOLDER_EVENT_LOG_IDENTITY;
        // Note that for backwards compatibility we don't
        // encode a version, later we will need to upgrade
        // the encoding to include a version
        let writer = Self::create_writer(
            path.as_ref(),
            &FOLDER_EVENT_LOG_IDENTITY,
            None,
        )
        .await?;

        FileIdentity::read_file(path.as_ref(), &FOLDER_EVENT_LOG_IDENTITY)
            .await?;

        let reader = Self::create_reader(path.as_ref()).await?;

        Ok(Self {
            file: Arc::new(Mutex::new((reader, writer))),
            data: path.as_ref().to_path_buf(),
            tree: Default::default(),
            identity: &FOLDER_EVENT_LOG_IDENTITY,
            version: None,
            phantom: std::marker::PhantomData,
        })
    }
}

#[async_trait]
impl EventLogExt<WriteEvent, MemoryBuffer, MemoryBuffer, MemoryInner>
    for EventLog<WriteEvent, MemoryBuffer, MemoryBuffer, MemoryInner>
{
    async fn iter(&self, reverse: bool) -> Result<Iter> {
        let content_offset = self.header_len() as u64;
        let read_stream = MemoryBuffer { inner: self.data() };
        let it: Iter = Box::new(
            FormatStream::<EventLogRecord, MemoryBuffer>::new_buffer(
                read_stream,
                self.identity,
                true,
                Some(content_offset),
                reverse,
            )
            .await?,
        );

        Ok(it)
    }

    fn tree(&self) -> &CommitTree {
        &self.tree
    }

    fn tree_mut(&mut self) -> &mut CommitTree {
        &mut self.tree
    }

    fn identity(&self) -> &'static [u8] {
        self.identity
    }

    fn version(&self) -> Option<u16> {
        self.version
    }

    fn file(&self) -> Arc<Mutex<(MemoryBuffer, MemoryBuffer)>> {
        Arc::clone(&self.file)
    }

    fn data(&self) -> MemoryInner {
        self.data.clone()
    }

    fn data_any(&self) -> &dyn std::any::Any {
        &self.data
    }

    async fn truncate(&mut self) -> Result<()> {
        unimplemented!("truncate on memory event log");
    }

    async fn rewind(
        &mut self,
        _commit: &CommitHash,
    ) -> Result<Vec<EventRecord>> {
        unimplemented!("rewind on memory event log");
    }
}

impl EventLog<WriteEvent, MemoryBuffer, MemoryBuffer, MemoryInner> {
    /// Create a new folder event log writing to memory.
    pub fn new() -> Self {
        use crate::constants::FOLDER_EVENT_LOG_IDENTITY;

        let reader = MemoryBuffer::new();
        let writer = reader.clone();
        let inner = Arc::clone(&reader.inner);

        Self {
            file: Arc::new(Mutex::new((reader, writer))),
            data: inner,
            tree: Default::default(),
            identity: &FOLDER_EVENT_LOG_IDENTITY,
            version: None,
            phantom: std::marker::PhantomData,
        }
    }
}

impl EventLog<WriteEvent, DiscLog, DiscLog, PathBuf> {
    /// Get a copy of this event log compacted.
    pub async fn compact(&self) -> Result<(Self, u64, u64)> {
        let old_size = self.data.metadata()?.len();

        // Get the reduced set of events
        let events =
            FolderReducer::new().reduce(self).await?.compact().await?;
        let temp = NamedTempFile::new()?;

        // Apply them to a temporary event log file
        let mut temp_event_log = Self::new(temp.path()).await?;
        temp_event_log.apply(events.iter().collect()).await?;

        let new_size = self.data.metadata()?.len();

        // Remove the existing event log file
        vfs::remove_file(&self.data).await?;

        // Move the temp file into place
        //
        // NOTE: we would prefer to rename but on linux we
        // NOTE: can hit ErrorKind::CrossesDevices
        //
        // But it's a nightly only variant so can't use it yet to
        // determine whether to rename or copy.
        vfs::copy(temp.path(), &self.data).await?;

        // Need to recreate the event log file and load the updated
        // commit tree
        let mut new_event_log = Self::new(&self.data).await?;
        new_event_log.load_tree().await?;

        Ok((new_event_log, old_size, new_size))
    }
}

impl EventLog<AccountEvent, DiscLog, DiscLog, PathBuf> {
    /// Create a new account event log file.
    pub async fn new_account<P: AsRef<Path>>(path: P) -> Result<Self> {
        use crate::{
            constants::ACCOUNT_EVENT_LOG_IDENTITY, encoding::VERSION,
        };
        let writer = Self::create_writer(
            path.as_ref(),
            &ACCOUNT_EVENT_LOG_IDENTITY,
            Some(VERSION),
        )
        .await?;

        FileIdentity::read_file(path.as_ref(), &ACCOUNT_EVENT_LOG_IDENTITY)
            .await?;

        let reader = Self::create_reader(path.as_ref()).await?;

        Ok(Self {
            file: Arc::new(Mutex::new((reader, writer))),
            data: path.as_ref().to_path_buf(),
            tree: Default::default(),
            identity: &ACCOUNT_EVENT_LOG_IDENTITY,
            version: Some(VERSION),
            phantom: std::marker::PhantomData,
        })
    }
}

impl EventLog<DeviceEvent, DiscLog, DiscLog, PathBuf> {
    /// Create a new device event log file.
    pub async fn new_device(path: impl AsRef<Path>) -> Result<Self> {
        use crate::{
            constants::DEVICE_EVENT_LOG_IDENTITY, encoding::VERSION,
        };
        let writer = Self::create_writer(
            path.as_ref(),
            &DEVICE_EVENT_LOG_IDENTITY,
            Some(VERSION),
        )
        .await?;

        FileIdentity::read_file(path.as_ref(), &DEVICE_EVENT_LOG_IDENTITY)
            .await?;

        let reader = Self::create_reader(path.as_ref()).await?;

        Ok(Self {
            file: Arc::new(Mutex::new((reader, writer))),
            data: path.as_ref().to_path_buf(),
            tree: Default::default(),
            identity: &DEVICE_EVENT_LOG_IDENTITY,
            version: Some(VERSION),
            phantom: std::marker::PhantomData,
        })
    }
}

#[cfg(feature = "files")]
impl EventLog<FileEvent, DiscLog, DiscLog, PathBuf> {
    /// Create a new file event log file.
    pub async fn new_file(path: impl AsRef<Path>) -> Result<Self> {
        use crate::{constants::FILE_EVENT_LOG_IDENTITY, encoding::VERSION};
        let writer = Self::create_writer(
            path.as_ref(),
            &FILE_EVENT_LOG_IDENTITY,
            Some(VERSION),
        )
        .await?;

        FileIdentity::read_file(path.as_ref(), &FILE_EVENT_LOG_IDENTITY)
            .await?;

        let reader = Self::create_reader(path.as_ref()).await?;

        Ok(Self {
            file: Arc::new(Mutex::new((reader, writer))),
            data: path.as_ref().to_path_buf(),
            tree: Default::default(),
            identity: &FILE_EVENT_LOG_IDENTITY,
            version: Some(VERSION),
            phantom: std::marker::PhantomData,
        })
    }
}
