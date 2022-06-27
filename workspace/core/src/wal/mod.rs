//! Write ahead log types and traits.
use crate::{
    commit_tree::CommitTree, events::WalEvent, vault::CommitHash, Result,
};

use serde_binary::{
    binary_rw::SeekStream, Decode, Deserializer, Encode,
    Result as BinaryResult, Serializer,
};

use time::{Duration, OffsetDateTime};

pub mod file;
pub mod memory;
pub mod reducer;

/// Trait for implementations that provide access to a write-ahead log (WAL).
pub trait WalProvider<'a> {
    /// The item yielded by the iterator implementation.
    type Item: WalItem;

    /// Append a log event to the write ahead log.
    fn append_event(&mut self, log_event: WalEvent<'_>)
        -> Result<CommitHash>;

    /// Read the event data from an item.
    fn event_data(&self, item: Self::Item) -> Result<WalEvent<'_>>;

    /// Get the commit tree for the log records.
    fn tree(&self) -> &CommitTree;

    /// Get an iterator of the log records.
    fn iter(
        &'a self,
    ) -> Result<Box<dyn DoubleEndedIterator<Item = Result<Self::Item>> + '_>>;
}

/// Trait for items yielded by the iterator.
pub trait WalItem: std::fmt::Debug {
    /// Get the commit hash for the item.
    fn commit(&self) -> [u8; 32];

    /// Get the time for the log record.
    fn time(&self) -> &LogTime;
}

/// Timestamp for the log record.
#[derive(Debug, Clone)]
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
#[derive(Debug, Clone)]
pub struct WalRecord(LogTime, CommitHash, pub Vec<u8>);

impl Encode for WalRecord {
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

impl Decode for WalRecord {
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

impl WalItem for &WalRecord {
    fn commit(&self) -> [u8; 32] {
        self.1 .0
    }

    fn time(&self) -> &LogTime {
        &self.0
    }
}
