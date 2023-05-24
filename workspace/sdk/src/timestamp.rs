//! Date and time that can be encoded to and from binary (12 bytes).
//!
//! Encoded as an i64 of the seconds since the UNIX epoch and
//! a u32 nanosecond offset from the second.

use serde::{Deserialize, Serialize};
use std::{
    fmt,
    io::{Write},
};

use filetime::FileTime;

use time::{
    format_description::{
        self,
        well_known::{Rfc2822, Rfc3339},
    },
    Date, Duration, Month, OffsetDateTime, Time, UtcOffset,
};

use crate::Result;

/// Timestamp for events and log records.
#[derive(
    Debug, Clone, Serialize, Deserialize, Ord, PartialOrd, Eq, PartialEq,
)]
pub struct Timestamp(
    #[serde(with = "time::serde::rfc3339")] pub(crate) OffsetDateTime,
);

impl Default for Timestamp {
    fn default() -> Self {
        Self(OffsetDateTime::now_utc())
    }
}

impl Timestamp {
    /// Create from a calendar date.
    pub fn from_calendar_date(
        year: i32,
        month: Month,
        day: u8,
    ) -> Result<Self> {
        let date = Date::from_calendar_date(year, month, day)?;
        let offset_date_time = OffsetDateTime::now_utc();
        let offset_date_time = offset_date_time.replace_date(date);
        let offset_date_time = offset_date_time.replace_time(Time::MIDNIGHT);
        Ok(Self(offset_date_time))
    }

    /// Parse from a simple date format YYYY-MM-DD.
    pub fn parse_simple_date(s: &str) -> Result<Self> {
        let date_separator =
            format_description::parse("[year]-[month]-[day]")?;
        let date = Date::parse(s, &date_separator)?;
        let offset_date_time = OffsetDateTime::now_utc();
        let offset_date_time = offset_date_time.replace_date(date);
        let offset_date_time = offset_date_time.replace_time(Time::MIDNIGHT);
        Ok(Self(offset_date_time))
    }

    /// Parse as RFC3339.
    pub fn parse_rfc3339(value: &str) -> Result<Self> {
        Ok(Self(OffsetDateTime::parse(value, &Rfc3339)?))
    }

    /// Convert to a short human-readable date and time without
    /// the timezone offset.
    pub fn to_date_time(&self) -> Result<String> {
        let format = format_description::parse(
            "[day] [month repr:short] [year] [hour]:[minute]:[second]",
        )?;
        Ok(self.0.format(&format)?)
    }

    /// Convert this timestamp to a RFC2822 formatted string.
    pub fn to_rfc2822(&self) -> Result<String> {
        Timestamp::rfc2822(&self.0)
    }

    /// Convert an offset date time to a RFC2822 formatted string.
    fn rfc2822(datetime: &OffsetDateTime) -> Result<String> {
        Ok(datetime.format(&Rfc2822)?)
    }

    /// Convert this timestamp to a RFC3339 formatted string.
    pub fn to_rfc3339(&self) -> Result<String> {
        Timestamp::rfc3339(&self.0)
    }

    /// Convert an offset date time to a RFC3339 formatted string.
    pub fn rfc3339(datetime: &OffsetDateTime) -> Result<String> {
        Ok(datetime.format(&Rfc3339)?)
    }

    /// Convert to a date component.
    pub fn into_date(self) -> Date {
        self.0.date()
    }

    /// Convert to a time component.
    pub fn into_time(self) -> Time {
        self.0.time()
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match UtcOffset::current_local_offset() {
            Ok(local_offset) => {
                let datetime = self.0;
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

impl From<OffsetDateTime> for Timestamp {
    fn from(value: OffsetDateTime) -> Self {
        Self(value)
    }
}

impl From<Timestamp> for OffsetDateTime {
    fn from(value: Timestamp) -> Self {
        value.0
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

#[cfg(test)]
mod test {
    use super::Timestamp;
    use crate::{decode, encode};
    use anyhow::Result;

    #[test]
    fn timestamp_encode() -> Result<()> {
        let timestamp: Timestamp = Default::default();
        let buffer = encode(&timestamp)?;
        let decoded: Timestamp = decode(&buffer)?;
        assert_eq!(timestamp, decoded);
        Ok(())
    }
}
