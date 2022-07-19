//! Write ahead log file.
//!
//! WAL files consist of a 4 identity bytes followed by one or more
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
    commit_tree::{hash, wal_commit_tree, CommitTree},
    constants::{WAL_EXT, WAL_IDENTITY},
    encode,
    events::WalEvent,
    iter::{wal_iter, FileItem, WalFileRecord},
    timestamp::Timestamp,
    CommitHash, Error, Result,
};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use binary_stream::{BinaryReader, Decode, Endian, SliceStream};
use tempfile::NamedTempFile;

use super::{reducer::WalReducer, WalItem, WalProvider, WalRecord};

/// A write ahead log that appends to a file.
pub struct WalFile {
    file_path: PathBuf,
    file: File,
    tree: CommitTree,
}

impl WalFile {
    /// Create the write ahead log file.
    fn create<P: AsRef<Path>>(path: P) -> Result<File> {
        let exists = path.as_ref().exists();

        if !exists {
            File::create(path.as_ref())?;
        }

        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(path.as_ref())?;

        let size = file.metadata()?.len();
        if size == 0 {
            file.write_all(&WAL_IDENTITY)?;
        }
        Ok(file)
    }

    fn encode_event(
        &self,
        event: WalEvent<'_>,
        last_commit: Option<CommitHash>,
    ) -> Result<(CommitHash, WalRecord)> {
        let time: Timestamp = Default::default();
        let bytes = encode(&event)?;
        let commit = CommitHash(hash(&bytes));

        let last_commit = if let Some(last_commit) = last_commit {
            last_commit
        } else {
            self.last_commit()?.unwrap_or_else(|| CommitHash([0u8; 32]))
        };

        let record = WalRecord(time, last_commit, commit, bytes);
        Ok((commit, record))
    }

    /// The file extension for WAL files.
    pub fn extension() -> &'static str {
        WAL_EXT
    }
}

impl WalProvider for WalFile {
    type Item = WalFileRecord;
    type Partial = Vec<u8>;

    fn new<P: AsRef<Path>>(file_path: P) -> Result<Self> {
        let file = WalFile::create(file_path.as_ref())?;
        Ok(Self {
            file,
            file_path: file_path.as_ref().to_path_buf(),
            tree: Default::default(),
        })
    }

    fn compact(&self) -> Result<(Self, u64, u64)> {
        let old_size = self.path().metadata()?.len();

        // Get the reduced set of events
        let events = WalReducer::new().reduce(self)?.compact()?;
        let temp = NamedTempFile::new()?;

        // Apply them to a temporary WAL file
        let mut temp_wal = WalFile::new(temp.path())?;
        temp_wal.apply(events, None)?;

        let new_size = temp_wal.path().metadata()?.len();

        // Remove the existing WAL file
        std::fs::remove_file(self.path())?;
        // Move the temp file into place
        std::fs::rename(temp.path(), self.path())?;

        let mut new_wal = Self::new(self.path())?;
        new_wal.load_tree()?;

        // Verify the new WAL tree
        wal_commit_tree(new_wal.path(), true, |_| {})?;

        // Need to recreate the WAL file and load the updated
        // commit tree
        Ok((new_wal, old_size, new_size))
    }

    fn write_buffer(&mut self, buffer: Vec<u8>) -> Result<()> {
        std::fs::write(self.path(), &buffer)?;
        self.load_tree()?;
        Ok(())
    }

    fn append_buffer(&mut self, buffer: Vec<u8>) -> Result<()> {
        // Get buffer of log records after the identity bytes
        let buffer = &buffer[WAL_IDENTITY.len()..];

        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(self.path())?;
        file.write_all(buffer)?;

        // Update with the new commit tree
        self.load_tree()?;
        Ok(())
    }

    fn tail(&self, item: Self::Item) -> Result<Self::Partial> {
        let mut partial = WAL_IDENTITY.to_vec();
        let start = item.offset().end;
        let mut file = File::open(&self.file_path)?;
        let end = file.metadata()?.len() as usize;

        if start < end {
            file.seek(SeekFrom::Start(start as u64))?;
            let mut buffer = vec![0; end - start];
            file.read_exact(buffer.as_mut_slice())?;
            partial.append(&mut buffer);
            Ok(partial)
        } else {
            Ok(partial)
        }
    }

    fn read_buffer(&self, record: &Self::Item) -> Result<Vec<u8>> {
        let mut file = File::open(&self.file_path)?;
        let offset = record.offset();
        let row_len = offset.end - offset.start;

        file.seek(SeekFrom::Start(offset.start as u64))?;

        let mut buf = vec![0u8; row_len];
        file.read_exact(&mut buf)?;

        Ok(buf)
    }

    fn path(&self) -> &PathBuf {
        &self.file_path
    }

    fn tree(&self) -> &CommitTree {
        &self.tree
    }

    fn apply(
        &mut self,
        events: Vec<WalEvent<'_>>,
        expect: Option<CommitHash>,
    ) -> Result<Vec<CommitHash>> {
        let mut buffer: Vec<u8> = Vec::new();
        let mut commits = Vec::new();
        let mut last_commit_hash = None;
        for event in events {
            let (commit, record) =
                self.encode_event(event, last_commit_hash)?;
            commits.push(commit);
            let mut buf = encode(&record)?;
            last_commit_hash = Some(CommitHash(hash(&buf)));
            buffer.append(&mut buf);
        }

        let mut hashes =
            commits.iter().map(|c| *c.as_ref()).collect::<Vec<_>>();

        let len = self.file_path.metadata()?.len();

        match self.file.write_all(&buffer) {
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
                            "WAL rollback on expected root hash mismatch"
                        );
                        self.file.set_len(len)?;
                        self.tree.rollback();
                    }
                }

                Ok(commits)
            }
            Err(e) => {
                tracing::debug!(
                    length = len,
                    "WAL rollback on buffer write error"
                );
                // In case of partial write attempt to truncate
                // to the previous file length restoring to the
                // previous state of the WAL log
                self.file.set_len(len)?;
                Err(Error::from(e))
            }
        }
    }

    fn append_event(&mut self, event: WalEvent<'_>) -> Result<CommitHash> {
        let (commit, record) = self.encode_event(event, None)?;
        let buffer = encode(&record)?;
        self.file.write_all(&buffer)?;
        self.tree.insert(*commit.as_ref());
        self.tree.commit();
        Ok(commit)
    }

    fn event_data(&self, item: &Self::Item) -> Result<WalEvent<'_>> {
        let value = item.value();

        // Use a different file handle as the owned `file` should
        // be used exclusively for appending
        let mut file = File::open(&self.file_path)?;

        file.seek(SeekFrom::Start(value.start as u64))?;
        let mut buffer = vec![0; value.end - value.start];
        file.read_exact(buffer.as_mut_slice())?;

        let mut stream = SliceStream::new(&buffer);
        let mut reader = BinaryReader::new(&mut stream, Endian::Big);
        let mut event: WalEvent = Default::default();
        event.decode(&mut reader)?;
        Ok(event)
    }

    fn load_tree(&mut self) -> Result<()> {
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

    fn clear(&mut self) -> Result<()> {
        self.file = File::create(&self.file_path)?;
        self.file.write_all(&WAL_IDENTITY)?;
        self.tree = CommitTree::new();
        Ok(())
    }

    fn iter(
        &self,
    ) -> Result<Box<dyn DoubleEndedIterator<Item = Result<Self::Item>> + '_>>
    {
        Ok(Box::new(wal_iter(&self.file_path)?))
    }
}

#[cfg(test)]
mod test {
    use anyhow::Result;
    use std::borrow::Cow;
    use tempfile::NamedTempFile;

    use super::*;
    use crate::{events::WalEvent, test_utils::*};

    fn mock_wal_file() -> Result<(NamedTempFile, WalFile, Vec<CommitHash>)> {
        let (encryption_key, _, _) = mock_encryption_key()?;
        let (_, mut vault, buffer) = mock_vault_file()?;

        let temp = NamedTempFile::new()?;
        let mut wal = WalFile::new(temp.path())?;

        let mut commits = Vec::new();

        // Create the vault
        let event = WalEvent::CreateVault(Cow::Owned(buffer));
        commits.push(wal.append_event(event)?);

        // Create a secret
        let (secret_id, _, _, _, event) = mock_vault_note(
            &mut vault,
            &encryption_key,
            "WAL Note",
            "This a WAL note secret.",
        )?;
        commits.push(wal.append_event(event.try_into()?)?);

        // Update the secret
        let (_, _, _, event) = mock_vault_note_update(
            &mut vault,
            &encryption_key,
            &secret_id,
            "WAL Note Edited",
            "This a WAL note secret that was edited.",
        )?;
        if let Some(event) = event {
            commits.push(wal.append_event(event.try_into()?)?);
        }

        Ok((temp, wal, commits))
    }

    #[test]
    fn wal_iter_forward() -> Result<()> {
        let (temp, wal, commits) = mock_wal_file()?;
        let mut it = wal.iter()?;
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

    #[test]
    fn wal_iter_backward() -> Result<()> {
        let (temp, wal, _) = mock_wal_file()?;
        let mut it = wal.iter()?;
        let _third_row = it.next_back().unwrap();
        let _second_row = it.next_back().unwrap();
        let _first_row = it.next_back().unwrap();
        assert!(it.next_back().is_none());
        temp.close()?;
        Ok(())
    }

    #[test]
    fn wal_iter_mixed() -> Result<()> {
        let (temp, wal, _) = mock_wal_file()?;
        let mut it = wal.iter()?;
        let _first_row = it.next().unwrap();
        let _third_row = it.next_back().unwrap();
        let _second_row = it.next_back().unwrap();
        assert!(it.next_back().is_none());
        assert!(it.next().is_none());
        temp.close()?;
        Ok(())
    }
}
