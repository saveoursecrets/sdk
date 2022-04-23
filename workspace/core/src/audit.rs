//! Types for audit logs.
use serde_binary::{
    Decode, Deserializer, Encode, Result as BinaryResult,
    Serializer,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc, NaiveDateTime};
use uuid::Uuid;

use crate::{
    address::AddressStr,
};

/// Audit log record (34 or 50 bytes).
///
/// * 8 bytes for the timestamp seconds.
/// * 4 bytes for the timestamp nanoseconds.
/// * 1 byte for the operation identifier.
/// * 20 bytes for the public address.
/// * 1 byte flag to indicate presence of vault UUID
/// * 16 bytes for the vault UUID.
#[derive(Debug)]
pub struct Log {
    time: DateTime<Utc>,
    operation: u8,
    address: AddressStr,
    vault: Option<Uuid>,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            time: Utc::now(),
            operation: 0,
            address: Default::default(),
            vault: None,
        }
    }
}

impl Log {
    /// Create a new audit log entry.
    pub fn new(operation: u8, address: AddressStr, vault: Option<Uuid>) -> Self {
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
        ser.writer.write_u8(self.operation)?;
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
        self.operation = de.reader.read_u8()?;
        // Address - by whom
        let address = de.reader.read_bytes(20)?;
        let address: [u8; 20] = address.as_slice().try_into()?;
        self.address = address.into();
        // Uuid - on vault
        let has_uuid = de.reader.read_bool()?;
        if has_uuid {
            let uuid: [u8; 16] = de.reader.read_bytes(16)?.as_slice().try_into()?;
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

    /// Append to a log destination.
    async fn append(&mut self, log: Log) -> std::result::Result<(), Self::Error>;
}
