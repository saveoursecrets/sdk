//! Types for audit logs.
use async_trait::async_trait;
use bitflags::bitflags;
use serde::{Deserialize, Serialize};
use serde_binary::{
    binary_rw::{BinaryReader, Endian, FileStream, OpenType, SeekStream},
    Decode, Deserializer, Encode, Error as BinaryError, Result as BinaryResult,
    Serializer,
};
use std::path::Path;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{
    address::AddressStr, file_identity::FileIdentity, operations::Operation,
    Error, Result,
};

/// Identity magic bytes (SOSA).
pub const IDENTITY: [u8; 4] = [0x53, 0x4F, 0x53, 0x41];

bitflags! {
    /// Bit flags for associated data.
    pub struct LogFlags: u16 {
        /// Indicates whether associated data is present.
        const DATA =        0b00000001;
        /// Indicates the data has a vault identifier.
        const DATA_VAULT =  0b00000010;
        /// Indicates the data has a secret identifier.
        const DATA_SECRET = 0b00000100;
    }
}

/// Audit log record.
///
/// An audit log record with no associated data is 36 bytes.
///
/// When associated data is available an additional 16 bytes is used
/// for operations on a vault and 32 bytes for operations on a secret.
///
/// The maximum size of a log record is thus 68 bytes.
///
/// * 2 bytes for bit flags.
/// * 8 bytes for the timestamp seconds.
/// * 4 bytes for the timestamp nanoseconds.
/// * 2 bytes for the operation identifier.
/// * 20 bytes for the public address.
/// * 16 or 32 bytes for the context data (one or two UUIDs).
#[derive(Debug, Serialize, Deserialize)]
pub struct Log {
    /// The time the log was created.
    pub time: OffsetDateTime,
    /// The operation being performed.
    pub operation: Operation,
    /// The address of the client performing the operation.
    pub address: AddressStr,
    /// Context data about the operation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<LogData>,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            time: OffsetDateTime::now_utc(),
            operation: Default::default(),
            address: Default::default(),
            data: None,
        }
    }
}

impl Log {
    /// Create a new audit log entry.
    pub fn new(
        operation: Operation,
        address: AddressStr,
        data: Option<LogData>,
    ) -> Self {
        Self {
            time: OffsetDateTime::now_utc(),
            operation,
            address,
            data,
        }
    }

    fn log_flags(&self) -> LogFlags {
        if let Some(data) = &self.data {
            let mut flags = LogFlags::empty();
            flags.set(LogFlags::DATA, true);
            match data {
                LogData::Vault(_) => {
                    flags.set(LogFlags::DATA_VAULT, true);
                }
                LogData::Secret(_, _) => {
                    flags.set(LogFlags::DATA_VAULT, true);
                    flags.set(LogFlags::DATA_SECRET, true);
                }
            }
            flags
        } else {
            LogFlags::empty()
        }
    }
}

impl Encode for Log {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        // Context bit flags
        let flags = self.log_flags();
        ser.writer.write_u16(flags.bits())?;
        // Time - the when
        let seconds = self.time.unix_timestamp();
        let nanos = self.time.nanosecond();
        ser.writer.write_i64(seconds)?;
        ser.writer.write_u32(nanos)?;
        // Operation - the what
        self.operation.encode(&mut *ser)?;
        // Address - by whom
        ser.writer.write_bytes(self.address.as_ref())?;
        // Data - context
        if flags.contains(LogFlags::DATA) {
            let data = self.data.as_ref().unwrap();
            data.encode(&mut *ser)?;
        }
        Ok(())
    }
}

impl Decode for Log {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        // Context bit flags
        let bits = de.reader.read_u16()?;
        // Time - the when
        let seconds = de.reader.read_i64()?;
        let nanos = de.reader.read_u32()?;
        self.time = OffsetDateTime::from_unix_timestamp(seconds)
            .map_err(Box::from)?
            + Duration::nanoseconds(nanos as i64);
        // Operation - the what
        self.operation.decode(&mut *de)?;
        // Address - by whom
        let address = de.reader.read_bytes(20)?;
        let address: [u8; 20] = address.as_slice().try_into()?;
        self.address = address.into();
        // Data - context
        if let Some(flags) = LogFlags::from_bits(bits) {
            if flags.contains(LogFlags::DATA) {
                if flags.contains(LogFlags::DATA_VAULT) {
                    let vault_id: [u8; 16] =
                        de.reader.read_bytes(16)?.as_slice().try_into()?;
                    if !flags.contains(LogFlags::DATA_SECRET) {
                        self.data =
                            Some(LogData::Vault(Uuid::from_bytes(vault_id)));
                    } else {
                        let secret_id: [u8; 16] =
                            de.reader.read_bytes(16)?.as_slice().try_into()?;
                        self.data = Some(LogData::Secret(
                            Uuid::from_bytes(vault_id),
                            Uuid::from_bytes(secret_id),
                        ));
                    }
                }
            }
        } else {
            return Err(BinaryError::Message(
                "log data flags has bad bits".to_string(),
            ));
        }
        Ok(())
    }
}

/// Associated data for an audit log record.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogData {
    /// Data for an associated vault.
    Vault(Uuid),
    /// Data for an associated secret.
    Secret(Uuid, Uuid),
}

impl Default for LogData {
    fn default() -> Self {
        let zero = [0u8; 16];
        Self::Vault(Uuid::from_bytes(zero))
    }
}

impl Encode for LogData {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        match self {
            LogData::Vault(vault_id) => {
                ser.writer.write_bytes(vault_id.as_bytes())?;
            }
            LogData::Secret(vault_id, secret_id) => {
                ser.writer.write_bytes(vault_id.as_bytes())?;
                ser.writer.write_bytes(secret_id.as_bytes())?;
            }
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
    pub fn new<P: AsRef<Path>>(
        path: P,
        expects_identity: bool,
    ) -> Result<Self> {
        let size = path.as_ref().metadata()?.len();
        if size == 0 {
            return Err(Error::EmptyFile(path.as_ref().to_path_buf()));
        } else if size < 4 {
            return Err(Error::FileTooSmall(path.as_ref().to_path_buf(), 4));
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
        } else {
            None
        }
    }
}
