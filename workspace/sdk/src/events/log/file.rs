//! Event log file.
//!
//! Event logs consist of a 4 identity bytes followed by one or more
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
    commit::{
        event_log_commit_tree_file, CommitHash, CommitState, CommitTree,
    },
    constants::{
        ACCOUNT_EVENT_LOG_IDENTITY, FILE_EVENT_LOG_IDENTITY,
        FOLDER_EVENT_LOG_IDENTITY,
    },
    encode,
    encoding::{encoding_options, VERSION, VERSION1},
    events::WriteEvent,
    formats::{
        event_log_stream, patch_stream, EventLogFileRecord,
        EventLogFileStream, FileItem,
    },
    timestamp::Timestamp,
    vfs::{self, File, OpenOptions},
    Error, Result,
};

#[cfg(feature = "account")]
use crate::events::AccountEvent;

#[cfg(feature = "files")]
use crate::events::FileEvent;

use std::{
    io::SeekFrom,
    path::{Path, PathBuf},
};

use futures::io::{BufReader, Cursor};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use binary_stream::futures::{BinaryReader, Decodable, Encodable};
use tempfile::NamedTempFile;

use super::{EventRecord, EventReducer};

/// Event log for changes to an account.
#[cfg(feature = "account")]
pub type AccountEventLog = EventLogFile<AccountEvent>;

/// Event log for changes to a folder.
pub type FolderEventLog = EventLogFile<WriteEvent>;

/// Event log for changes to external files.
#[cfg(feature = "files")]
pub type FileEventLog = EventLogFile<FileEvent>;

/// An event log that appends to a file.
pub struct EventLogFile<T>
where
    T: Default + Encodable + Decodable,
{
    file_path: PathBuf,
    file: File,
    tree: CommitTree,
    identity: &'static [u8],
    version: Option<u16>,
    phantom: std::marker::PhantomData<T>,
}

impl<T: Default + Encodable + Decodable> EventLogFile<T> {
    /// Create the event log file.
    async fn create<P: AsRef<Path>>(
        path: P,
        identity: &'static [u8],
        encoding_version: Option<u16>,
    ) -> Result<File> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())
            .await?;

        let size = file.metadata().await?.len();
        if size == 0 {
            let mut header = identity.to_vec();
            if let Some(version) = encoding_version {
                header.extend_from_slice(&version.to_le_bytes());
            }
            file.write_all(&header).await?;
            file.flush().await?;
        }
        Ok(file)
    }

    /// Encode an event into a record.
    async fn encode_event(
        &self,
        event: &T,
        last_commit: Option<CommitHash>,
    ) -> Result<(CommitHash, EventRecord)> {
        let time: Timestamp = Default::default();
        let bytes = encode(event).await?;

        let commit = CommitHash(CommitTree::hash(&bytes));

        let last_commit = if let Some(last_commit) = last_commit {
            last_commit
        } else {
            self.last_commit().await?.unwrap_or(CommitHash([0u8; 32]))
        };

        let record = EventRecord(time, last_commit, commit, bytes);
        Ok((commit, record))
    }

    /// Length of the file magic bytes and optional
    /// encoding version.
    fn header_len(&self) -> usize {
        let mut len = self.identity.len();
        if let Some(version) = self.version {
            len += (u16::BITS / 8) as usize;
        }
        len
    }

    /// Header bytes.
    fn header(&self) -> Vec<u8> {
        let mut header = self.identity.to_vec();
        if let Some(version) = self.version {
            header.extend_from_slice(&version.to_le_bytes());
        }
        header
    }

    /// Read encoding version from the file on disc.
    pub async fn read_file_version(&self) -> Result<u16> {
        if let Some(_) = &self.version {
            let mut file =
                OpenOptions::new().read(true).open(&self.file_path).await?;
            file.seek(SeekFrom::Start(self.identity.len() as u64))
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

    /// Get an iterator of the log records.
    pub async fn iter(&self) -> Result<EventLogFileStream> {
        let content_offset = self.header_len() as u64;
        event_log_stream(&self.file_path, self.identity, content_offset).await
    }

    /// Replace this event log with the contents of the buffer.
    ///
    /// The buffer should start with the event log identity bytes.
    pub async fn write_buffer(&mut self, buffer: &[u8]) -> Result<()> {
        vfs::write(self.path(), buffer).await?;
        self.load_tree().await?;
        Ok(())
    }

    /// Append the buffer to the contents of this event log.
    ///
    /// The buffer should start with the event log identity bytes.
    pub async fn append_buffer(&mut self, buffer: Vec<u8>) -> Result<()> {
        // Get buffer of log records after the identity bytes
        let buffer = &buffer[self.header_len()..];

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
        self.load_tree().await?;

        Ok(())
    }

    /// Get the tail after the given item until the end of the log.
    pub async fn tail(&self, item: EventLogFileRecord) -> Result<Vec<u8>> {
        let mut partial = self.header();
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

    /// Read the bytes for the encoded write event
    /// inside the log record.
    pub async fn read_event_buffer(
        &self,
        record: &EventLogFileRecord,
    ) -> Result<Vec<u8>> {
        let mut file = File::open(&self.file_path).await?;
        let offset = record.value();
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
        events: Vec<&T>,
    ) -> Result<Vec<CommitHash>> {
        let mut buffer: Vec<u8> = Vec::new();
        let mut commits = Vec::new();
        let mut last_commit_hash = self.last_commit().await?;
        for event in events {
            let (commit, record) =
                self.encode_event(event, last_commit_hash).await?;
            commits.push(commit);
            let mut buf = encode(&record).await?;
            last_commit_hash = Some(*record.commit());
            buffer.append(&mut buf);
        }

        let mut hashes =
            commits.iter().map(|c| *c.as_ref()).collect::<Vec<_>>();

        let len = self.file.metadata().await?.len();

        match self.file.write_all(&buffer).await {
            Ok(_) => {
                self.tree.append(&mut hashes);
                self.tree.commit();
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
    pub async fn append_event(&mut self, event: &T) -> Result<CommitHash> {
        let mut commits = self.apply(vec![event]).await?;
        Ok(commits.remove(0))
    }

    /// Read the event data from an item.
    pub async fn event_data(&self, item: &EventLogFileRecord) -> Result<T> {
        let value = item.value();

        // Use a different file handle as the owned `file` should
        // be used exclusively for appending
        let mut file = File::open(&self.file_path).await?;

        file.seek(SeekFrom::Start(value.start)).await?;
        let mut buffer = vec![0; (value.end - value.start) as usize];
        file.read_exact(buffer.as_mut_slice()).await?;

        let mut stream = BufReader::new(Cursor::new(&mut buffer));
        let mut reader = BinaryReader::new(&mut stream, encoding_options());
        let mut event: T = Default::default();
        event.decode(&mut reader).await?;
        Ok(event)
    }

    /// Load any cached data into the event log implementation
    /// to build a commit tree in memory.
    pub async fn load_tree(&mut self) -> Result<()> {
        let mut commits = Vec::new();
        let mut it = self.iter().await?;
        while let Some(record) = it.next_entry().await? {
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
        self.file.write_all(&self.identity).await?;
        self.file.flush().await?;
        self.tree = CommitTree::new();
        Ok(())
    }

    /// Read the last commit hash from the file.
    pub async fn last_commit(&self) -> Result<Option<CommitHash>> {
        let file_len = self.file.metadata().await?.len() as usize;
        if file_len > self.header_len() {
            let mut it = self.iter().await?.rev();
            if let Some(record) = it.next_entry().await? {
                Ok(Some(CommitHash(record.commit())))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Get a diff of the records after the record with the
    /// given commit hash.
    ///
    /// Iterates backwards from the end of the event log.
    pub async fn diff(&self, commit: [u8; 32]) -> Result<Option<Vec<u8>>> {
        let mut it = self.iter().await?.rev();
        while let Some(record) = it.next_entry().await? {
            if record.commit() == commit {
                return Ok(Some(self.tail(record).await?));
            }
        }
        Ok(None)
    }

    /// Get a patch from these event logs until a specific commit.
    ///
    /// Searches backwards until it finds the specified commit if given; if
    /// no commit is given the patch will include all events.
    ///
    /// Does not include the target commit in the patch.
    pub async fn patch_until(
        &self,
        commit: Option<&CommitHash>,
    ) -> Result<Vec<EventRecord>> {
        let mut events = Vec::new();
        let mut it = self.iter().await?.rev();
        while let Some(record) = it.next_entry().await? {
            if let Some(commit) = commit {
                if &record.commit() == commit.as_ref() {
                    return Ok(events);
                }
            }
            let buffer = self.read_event_buffer(&record).await?;
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

            /*
            if let Some(last_commit) = self.last_commit().await? {
                if &last_commit != commit {
                    return Err(Error::CommitNotFound(*commit));
                }
            } else {
            }
            */

            return Err(Error::CommitNotFound(*commit));
        }

        Ok(events)
    }

    /// Truncate the backing storage to an empty file.
    pub async fn truncate(&mut self) -> Result<()> {
        // Workaround for set_len(0) failing with "Access Denied" on Windows
        // SEE: https://github.com/rust-lang/rust/issues/105437
        let _ = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.file_path)
            .await;

        self.file.seek(SeekFrom::Start(0)).await?;
        self.file.write_all(&self.identity).await?;
        self.file.flush().await?;
        Ok(())
    }

    /// Get the commit state of this event log.
    ///
    /// The event log must already have some commits.
    pub async fn commit_state(&self) -> Result<CommitState> {
        let last_commit =
            self.last_commit().await?.ok_or(Error::NoRootCommit)?;
        let head = self.tree.head()?;
        Ok((last_commit, head))
    }
}

impl EventLogFile<WriteEvent> {
    /// Create a new folder event log file.
    pub async fn new_folder<P: AsRef<Path>>(file_path: P) -> Result<Self> {
        // Note that for backwards compatibility we don't
        // encode a version, later we will need to upgrade
        // the encoding to include a version
        let file = Self::create(
            file_path.as_ref(),
            &FOLDER_EVENT_LOG_IDENTITY,
            None,
        )
        .await?;
        Ok(Self {
            file,
            file_path: file_path.as_ref().to_path_buf(),
            tree: Default::default(),
            identity: &FOLDER_EVENT_LOG_IDENTITY,
            version: None,
            phantom: std::marker::PhantomData,
        })
    }

    /// Get a copy of this event log compacted.
    pub async fn compact(&self) -> Result<(Self, u64, u64)> {
        let old_size = self.path().metadata()?.len();

        // Get the reduced set of events
        let events =
            EventReducer::new().reduce(self).await?.compact().await?;
        let temp = NamedTempFile::new()?;

        // Apply them to a temporary event log file
        let mut temp_event_log = Self::new_folder(temp.path()).await?;
        temp_event_log.apply(events.iter().collect()).await?;

        let new_size = temp_event_log.file().metadata().await?.len();

        // Remove the existing event log file
        vfs::remove_file(self.path()).await?;
        // Move the temp file into place
        //
        // NOTE: we would prefer to rename but on linux we
        // NOTE: can hit ErrorKind::CrossesDevices
        //
        // But it's a nightly only variant so can't use it yet to
        // determine whether to rename or copy.
        vfs::copy(temp.path(), self.path()).await?;

        let mut new_event_log = Self::new_folder(self.path()).await?;
        new_event_log.load_tree().await?;

        // Verify the new event log tree
        event_log_commit_tree_file(new_event_log.path(), true, |_| {})
            .await?;

        // Need to recreate the event log file and load the updated
        // commit tree
        Ok((new_event_log, old_size, new_size))
    }
}

#[cfg(feature = "account")]
impl EventLogFile<AccountEvent> {
    /// Create a new account event log file.
    pub async fn new_account<P: AsRef<Path>>(file_path: P) -> Result<Self> {
        let file = Self::create(
            file_path.as_ref(),
            &ACCOUNT_EVENT_LOG_IDENTITY,
            Some(VERSION),
        )
        .await?;
        Ok(Self {
            file,
            file_path: file_path.as_ref().to_path_buf(),
            tree: Default::default(),
            identity: &ACCOUNT_EVENT_LOG_IDENTITY,
            version: Some(VERSION),
            phantom: std::marker::PhantomData,
        })
    }
}

#[cfg(feature = "files")]
impl EventLogFile<FileEvent> {
    /// Create a new file event log file.
    pub async fn new_file<P: AsRef<Path>>(file_path: P) -> Result<Self> {
        let file = Self::create(
            file_path.as_ref(),
            &FILE_EVENT_LOG_IDENTITY,
            Some(VERSION),
        )
        .await?;
        Ok(Self {
            file,
            file_path: file_path.as_ref().to_path_buf(),
            tree: Default::default(),
            identity: &FILE_EVENT_LOG_IDENTITY,
            version: Some(VERSION),
            phantom: std::marker::PhantomData,
        })
    }
}

#[cfg(test)]
mod test {
    use anyhow::Result;
    use tempfile::NamedTempFile;

    use super::*;
    use crate::{
        crypto::{csprng, AccessKey, SecureAccessKey},
        events::WriteEvent,
        passwd::diceware::generate_passphrase,
        test_utils::*,
        vault::VaultId,
    };
    use rand::Rng;

    async fn mock_account_event_log(
    ) -> Result<(NamedTempFile, AccountEventLog)> {
        let temp = NamedTempFile::new()?;
        let event_log = AccountEventLog::new_account(temp.path()).await?;
        Ok((temp, event_log))
    }

    async fn mock_folder_event_log() -> Result<(NamedTempFile, FolderEventLog)>
    {
        let temp = NamedTempFile::new()?;
        let event_log = FolderEventLog::new_folder(temp.path()).await?;
        Ok((temp, event_log))
    }

    async fn mock_event_log_file(
    ) -> Result<(NamedTempFile, FolderEventLog, Vec<CommitHash>)> {
        let (encryption_key, _, _) = mock_encryption_key()?;
        let (_, mut vault, buffer) = mock_vault_file().await?;

        let (temp, mut event_log) = mock_folder_event_log().await?;

        let mut commits = Vec::new();

        // Create the vault
        let event = WriteEvent::CreateVault(buffer);
        commits.push(event_log.append_event(&event).await?);

        // Create a secret
        let (secret_id, _, _, _, event) = mock_vault_note(
            &mut vault,
            &encryption_key,
            "event log Note",
            "This a event log note secret.",
        )
        .await?;
        commits.push(event_log.append_event(&event).await?);

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
            commits.push(event_log.append_event(&event).await?);
        }

        Ok((temp, event_log, commits))
    }

    #[tokio::test]
    async fn folder_event_log_iter_forward() -> Result<()> {
        let (temp, event_log, commits) = mock_event_log_file().await?;
        let mut it = event_log.iter().await?;
        let first_row = it.next_entry().await?.unwrap();
        let second_row = it.next_entry().await?.unwrap();
        let third_row = it.next_entry().await?.unwrap();

        assert_eq!(commits.get(0).unwrap().as_ref(), &first_row.commit());
        assert_eq!(commits.get(1).unwrap().as_ref(), &second_row.commit());
        assert_eq!(commits.get(2).unwrap().as_ref(), &third_row.commit());

        assert!(it.next_entry().await?.is_none());
        temp.close()?;
        Ok(())
    }

    #[tokio::test]
    async fn folder_event_log_iter_backward() -> Result<()> {
        let (temp, event_log, _) = mock_event_log_file().await?;
        let mut it = event_log.iter().await?.rev();
        let _third_row = it.next_entry().await?.unwrap();
        let _second_row = it.next_entry().await?.unwrap();
        let _first_row = it.next_entry().await?.unwrap();
        assert!(it.next_entry().await?.is_none());
        temp.close()?;
        Ok(())
    }

    #[tokio::test]
    async fn event_log_last_commit() -> Result<()> {
        let (temp, mut event_log) = mock_folder_event_log().await?;
        let (_, _vault, buffer) = mock_vault_file().await?;

        assert!(event_log.last_commit().await?.is_none());

        let event = WriteEvent::CreateVault(buffer);
        event_log.append_event(&event).await?;

        assert!(event_log.last_commit().await?.is_some());

        // Patch with all events
        let patch = event_log.patch_until(None).await?;
        assert_eq!(1, patch.len());

        // Patch is empty as the target commit is the empty commit
        let last_commit = event_log.last_commit().await?;
        let patch = event_log.patch_until(last_commit.as_ref()).await?;
        assert_eq!(0, patch.len());

        temp.close()?;
        Ok(())
    }

    #[cfg(feature = "account")]
    #[tokio::test]
    async fn account_event_log() -> Result<()> {
        let (temp, mut event_log) = mock_account_event_log().await?;

        let folder = VaultId::new_v4();
        let secret_key: [u8; 32] = csprng().gen();
        let (password, _) = generate_passphrase()?;
        let access_key: AccessKey = password.into();
        let key =
            SecureAccessKey::encrypt(&access_key, &secret_key, None).await?;
        event_log
            .apply(vec![
                &AccountEvent::CreateFolder(folder, key),
                &AccountEvent::DeleteFolder(folder),
            ])
            .await?;

        assert!(event_log.tree().len() > 0);
        assert!(event_log.tree().root().is_some());
        assert!(event_log.last_commit().await.is_ok());

        temp.close()?;
        Ok(())
    }
}
