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
//! | 4 row length | 12 timestamp | 32 hash | 4 data length | data | 4 row length |
//! ```
//!
use crate::{
    commit_tree::{hash, CommitTree},
    events::WalEvent,
    file_identity::{FileIdentity, WAL_IDENTITY},
    timestamp::Timestamp,
    vault::{encode, CommitHash},
    Result,
};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    ops::Range,
    path::{Path, PathBuf},
};

use serde_binary::{
    binary_rw::{
        BinaryReader, Endian, FileStream, OpenType, SeekStream, SliceStream,
    },
    Decode, Deserializer, Result as BinaryResult,
};

use super::{WalItem, WalProvider, WalRecord};

/// Reference to a row in the write ahead log.
#[derive(Default, Debug)]
pub struct WalFileRecord {
    /// Byte offset for the record.
    offset: Range<usize>,
    /// The time the row was created.
    time: Timestamp,
    /// The commit hash for the value.
    commit: [u8; 32],
    /// The byte range for the value.
    value: Range<usize>,
}

impl WalFileRecord {
    /// Read the bytes for the row value into an owned buffer.
    pub fn read_value<'a>(
        &self,
        reader: &mut BinaryReader<'a>,
    ) -> Result<Vec<u8>> {
        let length = self.value.end - self.value.start;
        reader.seek(self.value.start)?;
        let value = reader.read_bytes(length)?;
        Ok(value)
    }
}

impl WalItem for WalFileRecord {
    fn offset(&self) -> &Range<usize> {
        &self.offset
    }

    fn commit(&self) -> [u8; 32] {
        self.commit
    }

    fn time(&self) -> &Timestamp {
        &self.time
    }
}

impl Decode for WalFileRecord {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        let mut time: Timestamp = Default::default();
        time.decode(&mut *de)?;
        let hash_bytes: [u8; 32] =
            de.reader.read_bytes(32)?.as_slice().try_into()?;
        self.commit = hash_bytes;
        Ok(())
    }
}

/// A write ahead log that appends to a file.
pub struct WalFile {
    file_path: PathBuf,
    file: File,
    tree: CommitTree,
}

impl WalFile {
    /// Create a new write ahead log file.
    pub fn new<P: AsRef<Path>>(file_path: P) -> Result<Self> {
        let file = WalFile::create(file_path.as_ref())?;
        Ok(Self {
            file,
            file_path: file_path.as_ref().to_path_buf(),
            tree: Default::default(),
        })
    }

    /// Create the write ahead log file.
    fn create<P: AsRef<Path>>(path: P) -> Result<File> {
        let exists = path.as_ref().exists();

        if !exists {
            let file = File::create(path.as_ref())?;
            drop(file);
        }

        let mut file = OpenOptions::new()
            .write(true)
            .append(true)
            .open(path.as_ref())?;

        let size = file.metadata()?.len();
        if size == 0 {
            let identity = FileIdentity(WAL_IDENTITY);
            let buffer = encode(&identity)?;
            file.write_all(&buffer)?;
        }
        Ok(file)
    }
}

impl WalProvider for WalFile {
    type Item = WalFileRecord;
    type Partial = Vec<u8>;

    fn tail(&self, item: Self::Item) -> Result<Self::Partial> {
        let mut partial = WAL_IDENTITY.to_vec();
        let start = item.offset.end;
        let mut file = File::open(&self.file_path)?;
        let end = file.metadata()?.len() as usize;

        if start < end {
            file.seek(SeekFrom::Start(start as u64))?;
            let mut buffer = vec![0; end - start];
            file.read_exact(buffer.as_mut_slice())?;
            partial.extend_from_slice(buffer.as_slice());
            Ok(partial)
        } else {
            Ok(partial)
        }
    }

    fn tree(&self) -> &CommitTree {
        &self.tree
    }

    fn append_event(
        &mut self,
        log_event: WalEvent<'_>,
    ) -> Result<CommitHash> {
        let log_time: Timestamp = Default::default();
        let log_bytes = encode(&log_event)?;
        let hash_bytes = hash(&log_bytes);
        self.tree.insert(hash_bytes);
        let log_commit = CommitHash(hash_bytes);
        let log_record = WalRecord(log_time, log_commit, log_bytes);
        let buffer = encode(&log_record)?;
        self.file.write_all(&buffer)?;
        self.tree.commit();
        Ok(log_commit)
    }

    fn event_data(&self, item: Self::Item) -> Result<WalEvent<'_>> {
        let value = item.value;

        // Use a different file handle as the owned `file` should
        // be used exclusively for appending
        let mut file = File::open(&self.file_path)?;

        file.seek(SeekFrom::Start(value.start as u64))?;
        let mut buffer = vec![0; value.end - value.start];
        file.read_exact(buffer.as_mut_slice())?;

        let mut stream = SliceStream::new(&buffer);
        let reader = BinaryReader::new(&mut stream, Endian::Big);
        let mut de = Deserializer { reader };
        let mut event: WalEvent = Default::default();
        event.decode(&mut de)?;
        Ok(event)
    }

    fn iter(
        &self,
    ) -> Result<Box<dyn DoubleEndedIterator<Item = Result<Self::Item>> + '_>>
    {
        Ok(Box::new(WalFileIterator::new(&self.file_path)?))
    }
}

/// Iterator for WAL files.
pub struct WalFileIterator {
    /// The file read stream.
    file_stream: FileStream,
    /// Byte offset for forward iteration.
    forward: Option<usize>,
    /// Byte offset for backward iteration.
    backward: Option<usize>,
}

impl WalFileIterator {
    fn new<P: AsRef<Path>>(file_path: P) -> Result<Self> {
        let mut file_stream =
            FileStream::new(file_path.as_ref(), OpenType::Open)?;
        let reader = BinaryReader::new(&mut file_stream, Endian::Big);
        let mut deserializer = Deserializer { reader };
        FileIdentity::read_identity(&mut deserializer, &WAL_IDENTITY)?;
        file_stream.seek(4)?;
        Ok(Self {
            file_stream,
            forward: Some(4),
            backward: None,
        })
    }

    /// Helper to decode the row time, commit and byte range.
    fn read_row(
        de: &mut Deserializer,
        offset: Range<usize>,
    ) -> Result<WalFileRecord> {
        let start = de.reader.tell()?;
        let mut row: WalFileRecord = Default::default();
        row.decode(&mut *de)?;

        row.offset = offset;

        // The byte range for the row value.
        let value_len = de.reader.read_u32()?;
        let begin = de.reader.tell()?;
        let end = begin + value_len as usize;
        row.value = begin..end;

        Ok(row)
    }

    /// Attempt to read the next log row.
    fn read_row_next(&mut self) -> Result<WalFileRecord> {
        let row_pos = self.forward.unwrap();

        let reader = BinaryReader::new(&mut self.file_stream, Endian::Big);
        let mut de = Deserializer { reader };
        de.reader.seek(row_pos)?;
        let row_len = de.reader.read_u32()?;

        // Position of the end of the row
        let row_end = row_pos + (row_len as usize + 8);

        let row = WalFileIterator::read_row(&mut de, row_pos..row_end)?;

        // Prepare position for next iteration
        self.forward = Some(row_end);

        Ok(row)
    }

    /// Attempt to read the next log row for backward iteration.
    fn read_row_next_back(&mut self) -> Result<WalFileRecord> {
        let row_pos = self.backward.unwrap();

        let reader = BinaryReader::new(&mut self.file_stream, Endian::Big);
        let mut de = Deserializer { reader };

        // Read in the reverse iteration row length
        de.reader.seek(row_pos - 4)?;
        let row_len = de.reader.read_u32()?;

        // Position of the beginning of the row
        let row_start = row_pos - (row_len as usize + 8);
        let row_end = row_start + (row_len as usize + 8);

        // Seek to the beginning of the row after the initial
        // row length so we can read in the row data
        de.reader.seek(row_start + 4)?;
        let row = WalFileIterator::read_row(&mut de, row_start..row_end)?;

        // Prepare position for next iteration.
        self.backward = Some(row_start);

        Ok(row)
    }
}

impl Iterator for WalFileIterator {
    type Item = Result<WalFileRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        const OFFSET: usize = WAL_IDENTITY.len();

        if let (Some(lpos), Some(rpos)) = (self.forward, self.backward) {
            if lpos == rpos {
                return None;
            }
        }

        match self.file_stream.len() {
            Ok(len) => {
                if len > OFFSET {
                    // Got to EOF
                    if let Some(lpos) = self.forward {
                        if lpos == len {
                            return None;
                        }
                    }

                    if self.forward.is_none() {
                        self.forward = Some(OFFSET);
                    }

                    Some(self.read_row_next())
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }
}

impl DoubleEndedIterator for WalFileIterator {
    fn next_back(&mut self) -> Option<Self::Item> {
        const OFFSET: usize = WAL_IDENTITY.len();

        if let (Some(lpos), Some(rpos)) = (self.forward, self.backward) {
            if lpos == rpos {
                return None;
            }
        }

        match self.file_stream.len() {
            Ok(len) => {
                if len > 4 {
                    // Got to EOF
                    if let Some(rpos) = self.backward {
                        if rpos == OFFSET {
                            return None;
                        }
                    }

                    if self.backward.is_none() {
                        self.backward = Some(len);
                    }
                    Some(self.read_row_next_back())
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod test {
    use anyhow::Result;
    use std::borrow::Cow;
    use tempfile::NamedTempFile;

    use super::*;
    use crate::{commit_tree::CommitTree, events::WalEvent, test_utils::*};

    fn mock_wal_file() -> Result<(NamedTempFile, WalFile, Vec<CommitHash>)> {
        let (encryption_key, _) = mock_encryption_key()?;
        let (_, mut vault, buffer) = mock_vault_file()?;

        let temp = NamedTempFile::new()?;
        let mut wal = WalFile::new(temp.path().to_path_buf())?;

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

        assert_eq!(commits.get(0).unwrap().as_ref(), &first_row.commit);
        assert_eq!(commits.get(1).unwrap().as_ref(), &second_row.commit);
        assert_eq!(commits.get(2).unwrap().as_ref(), &third_row.commit);

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
