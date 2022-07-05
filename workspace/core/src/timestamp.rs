//! UNIX timestamp that can be encoded to and from binary (12 bytes).
//!
//! Encoded as an i64 of the seconds since the UNIX epoch and
//! a u32 nanosecond offset from the second.
use serde::{Deserialize, Serialize};
use serde_binary::{
    Decode, Deserializer, Encode, Result as BinaryResult, Serializer,
};
use std::fmt;

use filetime::FileTime;

use time::{
    format_description::well_known::{Rfc2822, Rfc3339},
    Duration, OffsetDateTime, UtcOffset,
};

use crate::Result;

/// Timestamp for events and log records.
#[derive(Debug, Clone, Serialize, Deserialize, PartialOrd, Eq, PartialEq)]
pub struct Timestamp(OffsetDateTime);

impl Default for Timestamp {
    fn default() -> Self {
        Self(OffsetDateTime::now_utc())
    }
}

impl Timestamp {
    /// Convert this timestamp to a RFC2822 formatted string.
    pub fn to_rfc2822(&self) -> Result<String> {
        Ok(Timestamp::rfc2822(&self.0)?)
    }

    /// Convert an offset date time to a RFC2822 formatted string.
    fn rfc2822(datetime: &OffsetDateTime) -> Result<String> {
        Ok(datetime.format(&Rfc2822)?)
    }

    /// Convert this timestamp to a RFC3339 formatted string.
    pub fn to_rfc3339(&self) -> Result<String> {
        Ok(Timestamp::rfc3339(&self.0)?)
    }

    /// Convert an offset date time to a RFC3339 formatted string.
    fn rfc3339(datetime: &OffsetDateTime) -> Result<String> {
        Ok(datetime.format(&Rfc3339)?)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match UtcOffset::current_local_offset() {
            Ok(local_offset) => {
                let datetime = self.0.clone();
                datetime.to_offset(local_offset);
                match Timestamp::rfc2822(&datetime) {
                    Ok(value) => {
                        write!(f, "{}", value)
                    }
                    Err(_) => {
                        write!(f, "{}", datetime)
                    }
                }
            }
            Err(_) => match self.to_rfc2822() {
                Ok(value) => {
                    write!(f, "{}", value)
                }
                Err(_) => {
                    write!(f, "{}", self.0)
                }
            },
        }
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

impl From<OffsetDateTime> for Timestamp {
    fn from(value: OffsetDateTime) -> Self {
        Self(value)
    }
}

impl TryFrom<FileTime> for Timestamp {
    type Error = crate::Error;

    fn try_from(value: FileTime) -> std::result::Result<Self, Self::Error> {
        let time = OffsetDateTime::from_unix_timestamp(value.seconds())?
            + Duration::nanoseconds(value.nanoseconds() as i64);
        Ok(time.into())
    }
}
