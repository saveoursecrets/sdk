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

/// Audit log record (50 bytes).
///
/// * 8 bytes for the timestamp seconds.
/// * 4 bytes for the timestamp nanoseconds.
/// * 20 bytes for the public address.
/// * 16 bytes for the vault UUID.
/// * 2 bytes for the operation identifier.
pub struct Log {
    time: DateTime<Utc>,
    address: AddressStr,
    vault: Uuid,
    operation: u16,
}

impl Log {
    /// Create a new audit log entry.
    pub fn new(address: AddressStr, vault: Uuid, operation: u16) -> Self {
        Self {
            time: Utc::now(),
            address,
            vault,
            operation,
        }
    }
}

impl Encode for Log {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        // Time
        let seconds = self.time.timestamp();
        let nanos = self.time.timestamp_subsec_nanos();
        ser.writer.write_i64(seconds)?;
        ser.writer.write_u32(nanos)?;
        // Address
        ser.writer.write_bytes(self.address.as_ref())?;
        // Uuid
        ser.writer.write_bytes(self.vault.as_bytes())?;
        // Operation
        ser.writer.write_u16(self.operation)?;
        Ok(())
    }
}

impl Decode for Log {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        // Time
        let seconds = de.reader.read_i64()?;
        let nanos = de.reader.read_u32()?;
        let date_time = NaiveDateTime::from_timestamp(seconds, nanos);
        self.time = DateTime::<Utc>::from_utc(date_time, Utc);
        // Address
        let address = de.reader.read_bytes(20)?;
        let address: [u8; 20] = address.as_slice().try_into()?;
        self.address = address.into();
        // Uuid
        let uuid: [u8; 16] = de.reader.read_bytes(16)?.as_slice().try_into()?;
        self.vault = Uuid::from_bytes(uuid);
        // Operation
        self.operation = de.reader.read_u16()?;
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
