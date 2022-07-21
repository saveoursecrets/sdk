//! UNIX timestamp that can be encoded to and from binary (12 bytes).
//!
//! Encoded as an i64 of the seconds since the UNIX epoch and
//! a u32 nanosecond offset from the second.
use binary_stream::{
    BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};
use serde::{Deserialize, Serialize};
use std::fmt;

use filetime::FileTime;

use chrono::{DateTime, Utc, NaiveDateTime};

use crate::Result;

/// Timestamp for events and log records.
#[derive(
    Debug, Clone, Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq,
)]
pub struct Timestamp(DateTime<Utc>);

impl Default for Timestamp {
    fn default() -> Self {
        Self(Utc::now())
    }
}

impl Timestamp {
    /// Convert this timestamp to a RFC2822 formatted string.
    pub fn to_rfc2822(&self) -> Result<String> {
        Ok(Timestamp::rfc2822(&self.0)?)
    }

    /// Convert an offset date time to a RFC2822 formatted string.
    fn rfc2822(datetime: &DateTime<Utc>) -> Result<String> {
        Ok(datetime.to_rfc2822())
    }

    /// Convert this timestamp to a RFC3339 formatted string.
    pub fn to_rfc3339(&self) -> Result<String> {
        Ok(Timestamp::rfc3339(&self.0)?)
    }

    /// Convert an offset date time to a RFC3339 formatted string.
    fn rfc3339(datetime: &DateTime<Utc>) -> Result<String> {
        Ok(datetime.to_rfc3339())
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_rfc2822() {
            Ok(value) => {
                write!(f, "{}", value)
            }
            Err(_) => {
                write!(f, "{}", self.0)
            }
        }
    }
}

impl Encode for Timestamp {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        let seconds = self.0.timestamp();
        let nanos = self.0.timestamp_subsec_nanos();
        writer.write_i64(seconds)?;
        writer.write_u32(nanos)?;
        Ok(())
    }
}

impl Decode for Timestamp {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        let seconds = reader.read_i64()?;
        let nanos = reader.read_u32()?;

        let date_time = NaiveDateTime::from_timestamp(seconds, nanos);
        self.0 = DateTime::from_utc(date_time, Utc);

        Ok(())
    }
}

impl From<DateTime<Utc>> for Timestamp {
    fn from(value: DateTime<Utc>) -> Self {
        Self(value)
    }
}

impl TryFrom<FileTime> for Timestamp {
    type Error = crate::Error;

    fn try_from(value: FileTime) -> std::result::Result<Self, Self::Error> {
        let date_time = NaiveDateTime::from_timestamp(
            value.seconds(), value.nanoseconds());
        let date_time = DateTime::from_utc(date_time, Utc);
        Ok(date_time.into())
    }
}
