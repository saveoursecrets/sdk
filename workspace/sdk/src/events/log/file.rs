//! Event log file.
//!
//! Event logd consist of a 4 identity bytes followed by one or more
//! rows of log records.
//!
//! Each row contains the row length prepended and appended so that
//! rows can be efficiently iterated in both directions.
//!
//! Row components with byte sizes:
//!
//! ```text
//! | 4 row length | 12 timestamp | 32 last commit hash | 32 commit hash | 4 data length | data | 4 row length |
//! ```
//!
//! The first row will contain a last commit hash that is all zero.
//!
use crate::{
    commit::{event_log_commit_tree_file, CommitHash, CommitTree},
    constants::EVENT_LOG_IDENTITY,
    encode,
    events::WriteEvent,
    formats::{event_log_iter, EventLogFileRecord, FileItem},
    timestamp::Timestamp,
    vfs::{self, File, OpenOptions},
    Error, Result,
};

use std::{
    io::{Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use binary_stream::{
    tokio::{BinaryReader, Decode},
    Endian,
};
use tempfile::NamedTempFile;

use super::{EventRecord, EventReducer};

/// An event log that appends to a file.
pub struct EventLogFile {
    file_path: PathBuf,
    file: File,
    tree: CommitTree,
}

impl EventLogFile {
    /// Create a new log file.
    pub async fn new<P: AsRef<Path>>(file_path: P) -> Result<Self> {
        let file = EventLogFile::create(file_path.as_ref()).await?;
        Ok(Self {
            file,
            file_path: file_path.as_ref().to_path_buf(),
            tree: Default::default(),
        })
    }

    /// Create the write ahead log file.
    async fn create<P: AsRef<Path>>(path: P) -> Result<File> {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(true)
            .open(path.as_ref())
            .await?;

        let size = file.metadata().await?.len();
        if size == 0 {
            file.write_all(&EVENT_LOG_IDENTITY).await?;
            file.flush().await?;
        }
        Ok(file)
    }

    async fn encode_event(
        &self,
        event: WriteEvent<'_>,
        last_commit: Option<CommitHash>,
    ) -> Result<(CommitHash, EventRecord)> {
        let time: Timestamp = Default::default();
        let bytes = encode(&event).await?;
        let commit = CommitHash(CommitTree::hash(&bytes));

        let last_commit = if let Some(last_commit) = last_commit {
            last_commit
        } else {
            self.last_commit().await?.unwrap_or(CommitHash([0u8; 32]))
        };

        let record = EventRecord(time, last_commit, commit, bytes);
        Ok((commit, record))
    }

    /// Get a copy of this event log compacted.
    pub async fn compact(&self) -> Result<(Self, u64, u64)> {
        let old_size = self.path().metadata()?.len();

        // Get the reduced set of events
        let events =
            EventReducer::new().reduce(self).await?.compact().await?;
        let temp = NamedTempFile::new()?;

        // Apply them to a temporary event log file
        let mut temp_event_log = EventLogFile::new(temp.path()).await?;
        temp_event_log.apply(events, None).await?;

        let new_size = temp_event_log.file().metadata().await?.len();

        // Remove the existing event log file
        vfs::remove_file(self.path()).await?;
        // Move the temp file into place
        vfs::rename(temp.path(), self.path()).await?;

        let mut new_event_log = Self::new(self.path()).await?;
        new_event_log.load_tree()?;

        // Verify the new event log tree
        event_log_commit_tree_file(new_event_log.path(), true, |_| {})
            .await?;

        // Need to recreate the event log file and load the updated
        // commit tree
        Ok((new_event_log, old_size, new_size))
    }

    /// Replace this event log with the contents of the buffer.
    ///
    /// The buffer should start with the event log identity bytes.
    pub async fn write_buffer(&mut self, buffer: &[u8]) -> Result<()> {
        vfs::write(self.path(), buffer).await?;
        self.load_tree()?;
        Ok(())
    }

    /// Append the buffer to the contents of this event log.
    ///
    /// The buffer should start with the event log identity bytes.
    pub async fn append_buffer(&mut self, buffer: Vec<u8>) -> Result<()> {
        // Get buffer of log records after the identity bytes
        let buffer = &buffer[EVENT_LOG_IDENTITY.len()..];

        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(self.path())
            .await?;
        file.write_all(buffer).await?;
        file.flush().await?;

        // FIXME: don't rebuild the entire commit tree from scratch
        // FIXME: but iterate the new commits in the buffer and
        // FIXME: append them to the existing tree

        // Update with the new commit tree
        self.load_tree()?;

        Ok(())
    }

    /// Get the tail after the given item until the end of the log.
    pub async fn tail(&self, item: EventLogFileRecord) -> Result<Vec<u8>> {
        let mut partial = EVENT_LOG_IDENTITY.to_vec();
        let start = item.offset().end as usize;
        let mut file = File::open(&self.file_path).await?;
        let end = file.metadata().await?.len() as usize;

        if start < end {
            file.seek(SeekFrom::Start(start as u64)).await?;
            let mut buffer = vec![0; end - start];
            file.read_exact(buffer.as_mut_slice()).await?;
            partial.append(&mut buffer);
            Ok(partial)
        } else {
            Ok(partial)
        }
    }

    /// Read or encode the bytes for the item.
    pub async fn read_buffer(
        &self,
        record: &EventLogFileRecord,
    ) -> Result<Vec<u8>> {
        let mut file = File::open(&self.file_path).await?;
        let offset = record.offset();
        let row_len = offset.end - offset.start;

        file.seek(SeekFrom::Start(offset.start)).await?;

        let mut buf = vec![0u8; row_len as usize];
        file.read_exact(&mut buf).await?;

        Ok(buf)
    }

    /// Get the path for this provider.
    pub fn path(&self) -> &PathBuf {
        &self.file_path
    }

    /// Get the file for this provider.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Get the commit tree for the log records.
    pub fn tree(&self) -> &CommitTree {
        &self.tree
    }

    /// Append a collection of events and commit the tree hashes
    /// only if all the events were successfully persisted.
    ///
    /// If any events fail this function will rollback the
    /// event log to it's previous state.
    pub async fn apply(
        &mut self,
        events: Vec<WriteEvent<'_>>,
        expect: Option<CommitHash>,
    ) -> Result<Vec<CommitHash>> {
        let mut buffer: Vec<u8> = Vec::new();
        let mut commits = Vec::new();
        let mut last_commit_hash = None;
        for event in events {
            let (commit, record) =
                self.encode_event(event, last_commit_hash).await?;
            commits.push(commit);
            let mut buf = encode(&record).await?;
            last_commit_hash = Some(CommitHash(CommitTree::hash(&buf)));
            buffer.append(&mut buf);
        }

        let mut hashes =
            commits.iter().map(|c| *c.as_ref()).collect::<Vec<_>>();

        let len = self.file.metadata().await?.len();

        match self.file.write_all(&buffer).await {
            Ok(_) => {
                self.tree.append(&mut hashes);
                self.tree.commit();

                // Rollback to previous state if expected commit hash
                // does not match the new commit hash
                if let (Some(expected), Some(root)) =
                    (expect, self.tree.root())
                {
                    let other_root: [u8; 32] = expected.into();
                    if other_root != root {
                        tracing::debug!(
                            length = len,
                            "event log rollback on expected root hash mismatch"
                        );
                        self.file.set_len(len).await?;
                        self.tree.rollback();
                    }
                }

                self.file.flush().await?;

                Ok(commits)
            }
            Err(e) => {
                tracing::debug!(
                    length = len,
                    "event log rollback on buffer write error"
                );
                // In case of partial write attempt to truncate
                // to the previous file length restoring to the
                // previous state of the event log log
                self.file.set_len(len).await?;
                Err(Error::from(e))
            }
        }
    }

    /// Append a log event and commit the hash to the commit tree.
    pub async fn append_event(
        &mut self,
        event: WriteEvent<'_>,
    ) -> Result<CommitHash> {
        let (commit, record) = self.encode_event(event, None).await?;
        let buffer = encode(&record).await?;
        self.file.write_all(&buffer).await?;
        self.file.flush().await?;
        self.tree.insert(*commit.as_ref());
        self.tree.commit();
        Ok(commit)
    }

    /// Read the event data from an item.
    pub async fn event_data(
        &self,
        item: &EventLogFileRecord,
    ) -> Result<WriteEvent<'_>> {
        let value = item.value();

        // Use a different file handle as the owned `file` should
        // be used exclusively for appending
        let mut file = File::open(&self.file_path).await?;

        file.seek(SeekFrom::Start(value.start)).await?;
        let mut buffer = vec![0; (value.end - value.start) as usize];
        file.read_exact(buffer.as_mut_slice()).await?;

        let mut stream = Cursor::new(&mut buffer);
        let mut reader = BinaryReader::new(&mut stream, Endian::Little);
        let mut event: WriteEvent = Default::default();

        event.decode(&mut reader).await?;
        Ok(event)
    }

    /// Load any cached data into the event log implementation
    /// to build a commit tree in memory.
    pub fn load_tree(&mut self) -> Result<()> {
        let mut commits = Vec::new();
        for record in self.iter()? {
            let record = record?;
            commits.push(record.commit());
        }
        self.tree = CommitTree::new();
        self.tree.append(&mut commits);
        self.tree.commit();
        Ok(())
    }

    /// Clear all events from this log file.
    pub async fn clear(&mut self) -> Result<()> {
        self.file = File::create(&self.file_path).await?;
        self.file.write_all(&EVENT_LOG_IDENTITY).await?;
        self.file.flush().await?;
        self.tree = CommitTree::new();
        Ok(())
    }

    /// Get an iterator of the log records.
    pub fn iter(
        &self,
    ) -> Result<
        Box<
            dyn DoubleEndedIterator<Item = Result<EventLogFileRecord>>
                + Send
                + '_,
        >,
    > {
        Ok(Box::new(event_log_iter(&self.file_path)?))
    }

    /// Get the last commit hash.
    pub async fn last_commit(&self) -> Result<Option<CommitHash>> {
        let mut it = self.iter()?;
        if let Some(record) = it.next_back() {
            let record = record?;
            let buffer = self.read_buffer(&record).await?;
            let last_record_hash = CommitTree::hash(&buffer);
            Ok(Some(CommitHash(last_record_hash)))
        } else {
            Ok(None)
        }
    }

    /// Get a diff of the records after the record with the
    /// given commit hash.
    pub async fn diff(&self, commit: [u8; 32]) -> Result<Option<Vec<u8>>> {
        let it = self.iter()?.rev();
        for record in it {
            let record = record?;
            if record.commit() == commit {
                return Ok(Some(self.tail(record).await?));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use anyhow::Result;
    use std::borrow::Cow;
    use tempfile::NamedTempFile;

    use super::*;
    use crate::{events::WriteEvent, test_utils::*};

    async fn mock_event_log_file(
    ) -> Result<(NamedTempFile, EventLogFile, Vec<CommitHash>)> {
        let (encryption_key, _, _) = mock_encryption_key()?;
        let (_, mut vault, buffer) = mock_vault_file().await?;

        let temp = NamedTempFile::new()?;
        let mut event_log = EventLogFile::new(temp.path()).await?;

        let mut commits = Vec::new();

        // Create the vault
        let event = WriteEvent::CreateVault(Cow::Owned(buffer));
        commits.push(event_log.append_event(event).await?);

        // Create a secret
        let (secret_id, _, _, _, event) = mock_vault_note(
            &mut vault,
            &encryption_key,
            "event log Note",
            "This a event log note secret.",
        )
        .await?;
        commits.push(event_log.append_event(event).await?);

        // Update the secret
        let (_, _, _, event) = mock_vault_note_update(
            &mut vault,
            &encryption_key,
            &secret_id,
            "event log Note Edited",
            "This a event log note secret that was edited.",
        )
        .await?;
        if let Some(event) = event {
            commits.push(event_log.append_event(event).await?);
        }

        Ok((temp, event_log, commits))
    }

    #[tokio::test]
    async fn event_log_iter_forward() -> Result<()> {
        let (temp, event_log, commits) = mock_event_log_file().await?;
        let mut it = event_log.iter()?;
        let first_row = it.next().unwrap()?;
        let second_row = it.next().unwrap()?;
        let third_row = it.next().unwrap()?;

        assert_eq!(commits.get(0).unwrap().as_ref(), &first_row.commit());
        assert_eq!(commits.get(1).unwrap().as_ref(), &second_row.commit());
        assert_eq!(commits.get(2).unwrap().as_ref(), &third_row.commit());

        assert!(it.next().is_none());
        temp.close()?;
        Ok(())
    }

    #[tokio::test]
    async fn event_log_iter_backward() -> Result<()> {
        let (temp, event_log, _) = mock_event_log_file().await?;
        let mut it = event_log.iter()?;
        let _third_row = it.next_back().unwrap();
        let _second_row = it.next_back().unwrap();
        let _first_row = it.next_back().unwrap();
        assert!(it.next_back().is_none());
        temp.close()?;
        Ok(())
    }

    #[tokio::test]
    async fn event_log_iter_mixed() -> Result<()> {
        let (temp, event_log, _) = mock_event_log_file().await?;
        let mut it = event_log.iter()?;
        let _first_row = it.next().unwrap();
        let _third_row = it.next_back().unwrap();
        let _second_row = it.next_back().unwrap();
        assert!(it.next_back().is_none());
        assert!(it.next().is_none());
        temp.close()?;
        Ok(())
    }
}
