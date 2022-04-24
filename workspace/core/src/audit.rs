//! Types for audit logs.
use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Serialize, Deserialize};
use serde_binary::{
    binary_rw::{
        BinaryReader, Endian, FileStream, OpenType,
    },
    Decode, Deserializer, Encode, Result as BinaryResult, Serializer,
};
use uuid::Uuid;
use std::path::Path;

use crate::{Result, Error, address::AddressStr, operations::Operation, file_identity::FileIdentity};

/// Identity magic bytes (SOSA).
pub const IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x41];

/// Audit log record (34 or 50 bytes).
///
/// * 8 bytes for the timestamp seconds.
/// * 4 bytes for the timestamp nanoseconds.
/// * 1 byte for the operation identifier.
/// * 20 bytes for the public address.
/// * 1 byte flag to indicate presence of vault UUID
/// * 16 bytes for the vault UUID.
#[derive(Debug, Serialize, Deserialize)]
pub struct Log {
    /// The time the log was created.
    pub time: DateTime<Utc>,
    /// The operation being performed.
    pub operation: Operation,
    /// The address of the client performing the operation.
    pub address: AddressStr,
    /// A vault the operation was being performed on.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault: Option<Uuid>,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            time: Utc::now(),
            operation: Default::default(),
            address: Default::default(),
            vault: None,
        }
    }
}

impl Log {
    /// Create a new audit log entry.
    pub fn new(
        operation: Operation,
        address: AddressStr,
        vault: Option<Uuid>,
    ) -> Self {
        Self {
            time: Utc::now(),
            operation,
            address,
            vault,
        }
    }
}

impl Encode for Log {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        // Time - the when
        let seconds = self.time.timestamp();
        let nanos = self.time.timestamp_subsec_nanos();
        ser.writer.write_i64(seconds)?;
        ser.writer.write_u32(nanos)?;
        // Operation - the what
        self.operation.encode(&mut *ser)?;
        // Address - by whom
        ser.writer.write_bytes(self.address.as_ref())?;
        // Uuid - on vault
        ser.writer.write_bool(self.vault.is_some())?;
        if let Some(vault) = &self.vault {
            ser.writer.write_bytes(vault.as_bytes())?;
        }
        Ok(())
    }
}

impl Decode for Log {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        // Time - the when
        let seconds = de.reader.read_i64()?;
        let nanos = de.reader.read_u32()?;
        let date_time = NaiveDateTime::from_timestamp(seconds, nanos);
        self.time = DateTime::<Utc>::from_utc(date_time, Utc);
        // Operation - the what
        self.operation.decode(&mut *de)?;
        // Address - by whom
        let address = de.reader.read_bytes(20)?;
        let address: [u8; 20] = address.as_slice().try_into()?;
        self.address = address.into();
        // Uuid - on vault
        let has_uuid = de.reader.read_bool()?;
        if has_uuid {
            let uuid: [u8; 16] =
                de.reader.read_bytes(16)?.as_slice().try_into()?;
            self.vault = Some(Uuid::from_bytes(uuid));
        }
        Ok(())
    }
}

/// Trait for types that append to an audit log.
#[async_trait]
pub trait Append {
    /// Error type for this implementation.
    type Error;

    /// Append a log to a destination.
    async fn append(
        &mut self,
        logs: Log,
    ) -> std::result::Result<(), Self::Error>;
}

/// Iterate a buffer any yield audit log records.
pub struct LogFileIterator {
    stream: FileStream,
    offset: usize,
    size: u64,
}

impl LogFileIterator {
    /// Create a new log file iterator.
    pub fn new<P: AsRef<Path>>(path: P, expects_identity: bool) -> Result<Self> {
        let size = path.as_ref().metadata()?.len();
        if size == 0 {
            return Err(Error::EmptyFile(path.as_ref().to_path_buf()));
        } else if size < 4 {
            return Err(
                Error::FileTooSmall(path.as_ref().to_path_buf(), 4));
        }

        let stream = FileStream::new(path.as_ref(), OpenType::Open)?;
        let mut it = Self {
            stream,
            offset: 0,
            size,
        };
        if expects_identity {
            it.read_identity()?;
        }
        Ok(it)
    }

    fn deserializer(&mut self) -> Result<Deserializer<'_>> {
        let reader = BinaryReader::new(&mut self.stream, Endian::Big);
        let mut de = Deserializer { reader };
        de.reader.seek(self.offset)?;
        Ok(de)
    }

    /// Attempt to read the identity bytes from the buffer and
    /// advance the offset.
    pub fn read_identity(&mut self) -> Result<()> {
        let mut de = self.deserializer()?;
        FileIdentity::read_identity(&mut de, &IDENTITY)?;
        self.offset = de.reader.tell()?;
        Ok(())
    }
}

impl Iterator for LogFileIterator {
    type Item = Log;

    fn next(&mut self) -> Option<Self::Item> {
        // WARN: this will fail on 32-bit platforms!
        let size = self.size as usize;

        if let Ok(mut de) = self.deserializer() {
            let pos = de.reader.tell().unwrap();
            if pos == size {
                // EOF
                return None;
            }

            let mut log: Log = Default::default();
            log.decode(&mut de).unwrap();
            self.offset = de.reader.tell().unwrap();
            Some(log)
        } else { None }
    }
}
