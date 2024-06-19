//! Events represent changes to accounts, folders and files.
//!
//! Events may be appended to *event log* files for persistence.
//!
//! Event logs maintain an in-memory merkle tree of commits to
//! enable syncing of data between devices.
//!
//! They are also used for some read events to maintain
//! an audit trail of actions.

use crate::{
    commit::{CommitHash, CommitTree},
    encode, Result, UtcDateTime,
};
use async_trait::async_trait;
use binary_stream::futures::{Decodable, Encodable};

mod account;
#[cfg(feature = "device")]
mod device;
mod event;
#[cfg(feature = "files")]
mod file;
mod log;
mod read;
mod types;
mod write;

pub use self::log::{
    patch::*, AccountEventLog, DiscData, DiscEventLog, DiscLog, EventLogExt,
    EventRecord, FolderEventLog, FolderReducer, MemoryData, MemoryEventLog,
    MemoryFolderLog, MemoryLog,
};
use crate::vault::VaultId;

#[cfg(feature = "device")]
pub use self::log::{DeviceEventLog, DeviceReducer};

#[cfg(feature = "files")]
pub use self::log::FileEventLog;

#[cfg(feature = "files")]
pub use self::log::FileReducer;

pub use account::AccountEvent;
#[cfg(feature = "device")]
pub use device::DeviceEvent;
pub use event::Event;
#[cfg(feature = "files")]
pub use file::FileEvent;
pub use read::ReadEvent;
pub use types::EventKind;
pub use write::WriteEvent;

/// Trait for events that can be written to an event log..
pub trait LogEvent {
    /// Get the event kind for this event.
    fn event_kind(&self) -> EventKind;
}

/// Types of event logs.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum EventLogType {
    /// Identity folder event log.
    Identity,
    /// Account event log.
    Account,
    /// Device event log.
    #[cfg(feature = "device")]
    Device,
    /// Files event log.
    #[cfg(feature = "files")]
    Files,
    /// Folder event log.
    Folder(VaultId),
}

/// Encode an event into a record.
#[async_trait]
pub trait IntoRecord {
    /// Encode an event into a record.
    async fn into_record(
        &self,
        time: Option<UtcDateTime>,
        last_commit: Option<CommitHash>,
    ) -> Result<EventRecord>;

    /// Encode an event into a record using a zero last commit
    /// and a date time from now.
    async fn default_record(&self) -> Result<EventRecord>;
}

#[async_trait]
impl<'a, T> IntoRecord for &'a T
where
    T: Default + Encodable + Decodable + Send + Sync,
{
    async fn default_record(&self) -> Result<EventRecord> {
        self.into_record(None, None).await
    }

    async fn into_record(
        &self,
        time: Option<UtcDateTime>,
        last_commit: Option<CommitHash>,
    ) -> Result<EventRecord> {
        let bytes = encode(*self).await?;
        let commit = CommitHash(CommitTree::hash(&bytes));
        Ok(EventRecord(
            time.unwrap_or_default(),
            last_commit.unwrap_or_default(),
            commit,
            bytes,
        ))
    }
}
