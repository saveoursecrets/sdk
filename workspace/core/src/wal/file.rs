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
//! ```norun
//! | 4 row length | 12 timestamp | 32 hash | 4 data length | data | 4 row length |
//! ```
//!
use crate::{
    commit_tree::hash,
    events::SyncEvent,
    file_identity::FileIdentity,
    vault::{encode, CommitHash},
    Result,
};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    ops::Range,
    path::{Path, PathBuf},
};

use serde_binary::{
    binary_rw::{BinaryReader, Endian, FileStream, SeekStream},
    Decode, Deserializer, Result as BinaryResult,
};

use super::{LogData, LogRecord, LogTime, WalIterator, WalProvider};

/// Identity magic bytes (SOSW).
pub const IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x57];

/// Byte offset that accounts for encoded time and hash digest.
///
/// 8 bytes for the timestamp seconds, 4 bytes for the timestamp
/// nanoseconds and 32 bytes for the commit hash.
const LOG_ROW_OFFSET: usize = 44;

/// Reference to a row in the write ahead log.
#[derive(Default, Debug)]
pub struct LogRow(LogTime, CommitHash, Range<usize>);

impl LogRow {
    /// Consume this log row and yield the commit hash.
    pub fn into_commit(self) -> CommitHash {
        self.1
    }
}

impl Decode for LogRow {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        let mut time: LogTime = Default::default();
        time.decode(&mut *de)?;
        let hash_bytes: [u8; 32] =
            de.reader.read_bytes(32)?.as_slice().try_into()?;
        self.1 = CommitHash(hash_bytes);
        Ok(())
    }
}

/// A write ahead log that appends to a file.
pub struct WalFile {
    file_path: PathBuf,
    file: File,
}

impl WalFile {
    /// Create a new write ahead log file.
    pub fn new<P: AsRef<Path>>(file_path: P) -> Result<Self> {
        let file = WalFile::create(file_path.as_ref())?;
        Ok(Self {
            file,
            file_path: file_path.as_ref().to_path_buf(),
        })
    }

    /// Get an iterator of the log record rows.
    pub fn iter(
        &self,
    ) -> Result<Box<dyn WalIterator<Item = Result<LogRow>>>> {
        Ok(Box::new(WalFileIterator::new(&self.file_path)?))
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
            let identity = FileIdentity(IDENTITY);
            let buffer = encode(&identity)?;
            file.write_all(&buffer)?;
        }
        Ok(file)
    }
}

impl WalProvider for WalFile {
    fn append_event(
        &mut self,
        log_event: &LogData<'_>,
    ) -> Result<CommitHash> {
        let log_time: LogTime = Default::default();
        let log_bytes = encode(log_event)?;
        let log_commit = CommitHash(hash(&log_bytes));
        let log_record = LogRecord(log_time, log_commit, log_bytes);
        let buffer = encode(&log_record)?;

        self.file.write_all(&buffer)?;
        Ok(log_commit)
    }
}

/// Iterator for WAL files.
pub struct WalFileIterator {
    /// The file path.
    file_path: PathBuf,
    /// The file read stream.
    file_stream: FileStream,
    /// Byte offset for forward iteration.
    forward: Option<usize>,
    /// Byte offset for backward iteration.
    backward: Option<usize>,
}

impl WalFileIterator {
    fn new<P: AsRef<Path>>(file_path: P) -> Result<Self> {
        let file = File::open(file_path.as_ref())?;
        let mut file_stream: FileStream = file.into();
        let reader = BinaryReader::new(&mut file_stream, Endian::Big);
        let mut deserializer = Deserializer { reader };
        FileIdentity::read_identity(&mut deserializer, &IDENTITY)?;
        file_stream.seek(4)?;
        Ok(Self {
            file_path: file_path.as_ref().to_path_buf(),
            file_stream,
            forward: Some(4),
            backward: None,
        })
    }

    /// Helper to decode the row time, commit and byte range.
    fn read_row(de: &mut Deserializer) -> Result<LogRow> {
        let start = de.reader.tell()?;
        let mut row: LogRow = Default::default();
        row.decode(&mut *de)?;

        // The byte range for the row value.
        let begin = start + LOG_ROW_OFFSET;
        let value_len = de.reader.read_u32()?;
        let end = begin + 4 + value_len as usize;
        row.2 = begin..end;

        Ok(row)
    }

    /// Attempt to read the next log row.
    fn read_row_next(&mut self) -> Result<LogRow> {
        let reader = BinaryReader::new(&mut self.file_stream, Endian::Big);
        let mut de = Deserializer { reader };
        let row_len = de.reader.read_u32()?;

        let row = WalFileIterator::read_row(&mut de)?;

        // Prepare position for next iteration
        let next_pos = row.2.end + 4;
        de.reader.seek(next_pos)?;
        self.forward = Some(next_pos);

        Ok(row)
    }

    /// Attempt to read the next log row for backward iteration.
    fn read_row_next_back(&mut self) -> Result<LogRow> {
        let rpos = self.backward.unwrap();

        let reader = BinaryReader::new(&mut self.file_stream, Endian::Big);
        let mut de = Deserializer { reader };
        de.reader.seek(rpos - 4)?;

        // Read in the reverse iteration row length
        let row_len = de.reader.read_u32()?;

        // Seek to the beginning of the row
        de.reader.seek(rpos - 4 - row_len as usize)?;

        let row = WalFileIterator::read_row(&mut de)?;

        // Prepare position for next iteration
        let next_pos = row.2.start - (LOG_ROW_OFFSET + 4);
        de.reader.seek(next_pos)?;
        self.backward = Some(next_pos);

        Ok(row)
    }
}

impl WalIterator for WalFileIterator {}

impl Iterator for WalFileIterator {
    type Item = Result<LogRow>;

    fn next(&mut self) -> Option<Self::Item> {
        if let (Some(lpos), Some(rpos)) = (self.forward, self.backward) {
            if lpos == rpos {
                return None;
            }
        }

        match self.file_stream.len() {
            Ok(len) => {
                // Got to EOF
                if let Some(lpos) = self.forward {
                    if lpos == len {
                        return None;
                    }
                }

                if len > 4 {
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
                        if rpos == IDENTITY.len() {
                            return None;
                        }
                    }

                    if self.backward.is_none() {
                        if let Err(e) = self.file_stream.seek(len) {
                            return Some(Err(e.into()));
                        }
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
    use super::*;
    use crate::{commit_tree::CommitTree, events::SyncEvent};
    use anyhow::Result;
    use tempfile::NamedTempFile;

    fn mock_wal_file() -> Result<(NamedTempFile, WalFile)> {
        let temp = NamedTempFile::new()?;
        // 4 byte magic identity

        // ROW
        // 4 byte row length
        // 12 byte timestamp
        // 32 byte commit hash
        // 4 byte value length (N)
        // [N] byte value
        // 4 byte row length

        // = 58 bytes for an empty payload
        //
        // = 178 bytes total

        let mut wal = WalFile::new(temp.path().to_path_buf())?;
        let payload: SyncEvent = SyncEvent::CreateVault;

        wal.append_event(&payload)?;
        wal.append_event(&payload)?;
        wal.append_event(&payload)?;

        Ok((temp, wal))
    }

    #[test]
    fn wal_iter_forward() -> Result<()> {
        let (temp, wal) = mock_wal_file()?;
        let mut it = wal.iter()?;
        let _first_row = it.next().unwrap();
        let _second_row = it.next().unwrap();
        let _third_row = it.next().unwrap();
        assert!(it.next().is_none());
        temp.close()?;
        Ok(())
    }

    #[test]
    fn wal_iter_backward() -> Result<()> {
        let (temp, wal) = mock_wal_file()?;
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
        let (temp, wal) = mock_wal_file()?;
        let mut it = wal.iter()?;
        let _first_row = it.next().unwrap();
        let _third_row = it.next_back().unwrap();
        let _second_row = it.next_back().unwrap();
        assert!(it.next_back().is_none());
        assert!(it.next().is_none());
        temp.close()?;
        Ok(())
    }

    #[test]
    fn wal_commit_tree() -> Result<()> {
        let (temp, wal) = mock_wal_file()?;
        let mut it = wal.iter()?;
        let tree = CommitTree::from_wal_iterator(&mut it)?;
        assert!(tree.root().is_some());
        temp.close()?;
        Ok(())
    }
}
