//! Event log types and traits.
use crate::{
    commit::CommitHash, decode, formats::EventLogRecord, Result, UtcDateTime,
};
use binary_stream::futures::Decodable;

mod file;
pub mod patch;
mod reducer;

#[cfg(feature = "files")]
pub use file::FileEventLog;

#[cfg(feature = "files")]
pub use reducer::FileReducer;

pub use file::{
    AccountEventLog, DeviceEventLog, DiscData, DiscEventLog, DiscLog,
    EventLogExt, FolderEventLog, MemoryData, MemoryEventLog, MemoryFolderLog,
    MemoryLog,
};
pub use reducer::{DeviceReducer, FolderReducer};

/// Record for a row in the event log.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct EventRecord(
    pub(crate) UtcDateTime,
    pub(crate) CommitHash,
    pub(crate) CommitHash,
    pub(crate) Vec<u8>,
);

impl EventRecord {
    /// Create an event record.
    pub fn new(
        time: UtcDateTime,
        last_commit: CommitHash,
        commit: CommitHash,
        event: Vec<u8>,
    ) -> Self {
        Self(time, last_commit, commit, event)
    }

    /// Date and time the record was created.
    pub fn time(&self) -> &UtcDateTime {
        &self.0
    }

    /// Last commit hash for the record.
    pub fn last_commit(&self) -> &CommitHash {
        &self.1
    }

    /// Set last commit hash for the record.
    pub fn set_last_commit(&mut self, commit: Option<CommitHash>) {
        self.1 = commit.unwrap_or_default();
    }

    /// Commit hash for the record.
    pub fn commit(&self) -> &CommitHash {
        &self.2
    }

    /// Record event bytes.
    pub fn event_bytes(&self) -> &[u8] {
        self.3.as_slice()
    }

    /// Size of the event buffer.
    pub fn size(&self) -> usize {
        self.3.len()
    }

    /// Decode this event record.
    pub async fn decode_event<T: Default + Decodable>(&self) -> Result<T> {
        decode(&self.3).await
    }
}

impl From<(EventLogRecord, Vec<u8>)> for EventRecord {
    fn from(value: (EventLogRecord, Vec<u8>)) -> Self {
        Self(
            value.0.time,
            CommitHash(value.0.last_commit),
            CommitHash(value.0.commit),
            value.1,
        )
    }
}

impl From<EventRecord> for (UtcDateTime, CommitHash, CommitHash, Vec<u8>) {
    fn from(value: EventRecord) -> Self {
        (value.0, value.1, value.2, value.3)
    }
}
