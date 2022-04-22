//! Types for audit logs.
use serde_binary::{
    Decode, Deserializer, Encode, Result as BinaryResult,
    Serializer,
};
use chrono::{DateTime, Utc, NaiveDateTime};
use uuid::Uuid;

use crate::{
    address::AddressStr,
};

/// Audit log record.
pub struct Log {
    time: DateTime<Utc>,
    address: AddressStr,
    vault: Uuid,
    operation: u8,
}

impl Log {
    /// Create a new audit log entry.
    pub fn new(address: AddressStr, vault: Uuid, operation: u8) -> Self {
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
        ser.writer.write_string(self.vault.to_string())?;
        // Operation
        ser.writer.write_u8(self.operation)?;
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
        self.vault =
            Uuid::parse_str(&de.reader.read_string()?).map_err(Box::from)?;
        // Operation
        self.operation = de.reader.read_u8()?;
        Ok(())
    }
}
