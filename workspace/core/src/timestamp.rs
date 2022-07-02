//! UNIX timestamp that can be encoded to and from binary (12 bytes).
//!
//! Encoded as an i64 of the seconds since the UNIX epoch and
//! a u32 nanosecond offset from the second.
use serde::{Deserialize, Serialize};
use serde_binary::{
    Decode, Deserializer, Encode, Result as BinaryResult, Serializer,
};
use std::fmt;

use time::{Duration, OffsetDateTime};

/// Timestamp for the log record.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Timestamp(OffsetDateTime);

impl Default for Timestamp {
    fn default() -> Self {
        Self(OffsetDateTime::now_utc())
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Encode for Timestamp {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        let seconds = self.0.unix_timestamp();
        let nanos = self.0.nanosecond();
        ser.writer.write_i64(seconds)?;
        ser.writer.write_u32(nanos)?;
        Ok(())
    }
}

impl Decode for Timestamp {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        let seconds = de.reader.read_i64()?;
        let nanos = de.reader.read_u32()?;
        self.0 = OffsetDateTime::from_unix_timestamp(seconds)
            .map_err(Box::from)?
            + Duration::nanoseconds(nanos as i64);
        Ok(())
    }
}
