//! Write ahead log implementation.
use crate::{
    commit_tree::hash,
    file_identity::FileIdentity,
    operations::Payload,
    vault::{encode, CommitHash},
    Result,
};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    marker::PhantomData,
    ops::Range,
    path::{Path, PathBuf},
};

use serde_binary::{
    binary_rw::{
        BinaryReader, BinaryWriter, Endian, FileStream, OpenType, ReadStream,
        SeekStream,
    },
    Decode, Deserializer, Encode, Error as BinaryError,
    Result as BinaryResult, Serializer,
};

use time::{Duration, OffsetDateTime};

/// Identity magic bytes (SOSW).
pub const IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x57];

/// Byte offset that accounts for encoded time and hash digest.
const LOG_ROW_OFFSET: usize = 128;

/// Timestamp for the log record.
pub struct LogTime(OffsetDateTime);

impl Default for LogTime {
    fn default() -> Self {
        Self(OffsetDateTime::now_utc())
    }
}

impl Encode for LogTime {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        let seconds = self.0.unix_timestamp();
        let nanos = self.0.nanosecond();
        ser.writer.write_i64(seconds)?;
        ser.writer.write_u32(nanos)?;
        Ok(())
    }
}

impl Decode for LogTime {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        let seconds = de.reader.read_i64()?;
        let nanos = de.reader.read_u32()?;
        self.0 = OffsetDateTime::from_unix_timestamp(seconds)
            .map_err(Box::from)?
            + Duration::nanoseconds(nanos as i64);
        Ok(())
    }
}

/// Record for a row in the write ahead log.
pub struct LogRecord(LogTime, CommitHash, Vec<u8>);

impl Encode for LogRecord {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        // Prepare the bytes for the row length
        let size_pos = ser.writer.tell()?;
        ser.writer.write_u32(0)?;

        // Encode the time component
        self.0.encode(&mut *ser)?;

        // Write the commit hash bytes
        ser.writer.write_bytes(self.1.as_ref())?;

        // FIXME: ensure the buffer size does not exceed u32

        // Write the data bytes
        ser.writer.write_u32(self.2.len() as u32)?;
        ser.writer.write_bytes(&self.2)?;

        // Backtrack to size_pos and write new length
        let row_pos = ser.writer.tell()?;
        let row_len = row_pos - (size_pos + 4);
        ser.writer.seek(size_pos)?;
        ser.writer.write_u32(row_len as u32)?;
        ser.writer.seek(row_pos)?;

        // Write out the row len at the end of the record too
        // so we can support double ended iteration
        ser.writer.write_u32(row_len as u32)?;

        Ok(())
    }
}

impl Decode for LogRecord {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        // Read in the row length
        let _ = de.reader.read_u32()?;

        // Decode the time component
        let mut time: LogTime = Default::default();
        time.decode(&mut *de)?;

        // Read the hash bytes
        let hash_bytes: [u8; 32] =
            de.reader.read_bytes(32)?.as_slice().try_into()?;

        // Read the data bytes
        let length = de.reader.read_u32()?;
        let buffer = de.reader.read_bytes(length as usize)?;

        self.0 = time;
        self.1 = CommitHash(hash_bytes);
        self.2 = buffer;

        // Read in the row length appended to the end of the record
        let _ = de.reader.read_u32()?;

        Ok(())
    }
}

/// Reference to a row in the write ahead log.
#[derive(Default)]
pub struct LogRow(LogTime, CommitHash, Range<usize>);

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

/// Data that is stored in each log record.
pub type LogData<'a> = Payload<'a>;

/// Trait for implementations that provide access to a WAL.
trait WalProvider {
    /// Append a log event to the write ahead log.
    fn append_event(&mut self, log_event: &LogData<'_>) -> Result<()>;

    /// Get an iterator for the provider.
    fn iter(&self) -> Result<Box<dyn WalIterator<Item = Result<LogRow>>>>;
}

/// Trait for implementations that can iterate a WAL log.
trait WalIterator: DoubleEndedIterator {}

/// A write ahead log that appends to a file.
pub struct WalFile<'a> {
    file_path: PathBuf,
    file: File,
    phantom: PhantomData<&'a ()>,
}

impl<'a> WalFile<'a> {
    /// Create a new write ahead log file.
    pub fn new(file_path: PathBuf) -> Result<Self> {
        let file = WalFile::create(&file_path)?;
        Ok(Self {
            file_path,
            file,
            phantom: PhantomData,
        })
    }

    /// Create the write ahead log file.
    pub fn create<P: AsRef<Path>>(path: P) -> Result<File> {
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

impl<'a> WalProvider for WalFile<'a> {
    fn append_event(&mut self, log_event: &LogData<'_>) -> Result<()> {
        let log_time: LogTime = Default::default();
        let log_bytes = encode(log_event)?;
        let log_commit = CommitHash(hash(&log_bytes));
        let log_record = LogRecord(log_time, log_commit, log_bytes);
        let buffer = encode(&log_record)?;
        self.file.write_all(&buffer)?;
        Ok(())
    }

    fn iter(&self) -> Result<Box<dyn WalIterator<Item = Result<LogRow>>>> {
        Ok(Box::new(WalFileIterator::new(&self.file_path)?))
    }
}

/// Iterator for WAL files.
pub struct WalFileIterator {
    file_stream: FileStream,
    // Byte offset for forward iteration.
    forward: Option<usize>,
    // Byte offset for backward iteration.
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
            file_stream,
            forward: Some(4),
            backward: None,
        })
    }

    /// Helper to decode the row time, commit and byte range.
    fn read_row(de: &mut Deserializer, row_len: u32) -> Result<LogRow> {
        let start = de.reader.tell()?;
        let mut row: LogRow = Default::default();
        row.decode(&mut *de)?;

        de.reader.seek(start + row_len as usize)?;
        let end = de.reader.tell()?;

        // The byte range for the row value.
        row.2 = (start + LOG_ROW_OFFSET)..end;
        Ok(row)
    }

    /// Attempt to read the next log row.
    fn read_row_next(&mut self) -> Result<LogRow> {
        let reader = BinaryReader::new(&mut self.file_stream, Endian::Big);
        let mut de = Deserializer { reader };
        let row_len = de.reader.read_u32()?;

        let row = WalFileIterator::read_row(&mut de, row_len)?;

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

        let row = WalFileIterator::read_row(&mut de, row_len)?;

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
