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
    AccountEventLog, DiscData, DiscEventLog, DiscLog, EventLogExt,
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
#[derive(Debug, Default, Copy, Clone)]
pub enum EventLogType {
    #[default]
    #[doc(hidden)]
    Noop,
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

impl EventLogType {
    /// Kind identifier of the identity log.
    pub const IDENTITY_LOG: u8 = 1;
    /// Kind identifier of the account log.
    pub const ACCOUNT_LOG: u8 = 2;
    /// Kind identifier of the device log.
    #[cfg(feature = "device")]
    pub const DEVICE_LOG: u8 = 3;
    /// Kind identifier of the files log.
    #[cfg(feature = "files")]
    pub const FILES_LOG: u8 = 4;
    /// Kind identifier of a folder log.
    pub const FOLDER_LOG: u8 = 5;
}

impl From<&EventLogType> for u8 {
    fn from(value: &EventLogType) -> Self {
        match value {
            EventLogType::Noop => panic!("attempt to convert a noop"),
            EventLogType::Identity => EventLogType::IDENTITY_LOG,
            EventLogType::Account => EventLogType::ACCOUNT_LOG,
            #[cfg(feature = "device")]
            EventLogType::Device => EventLogType::DEVICE_LOG,
            #[cfg(feature = "files")]
            EventLogType::Files => EventLogType::FILES_LOG,
            EventLogType::Folder(_) => EventLogType::FOLDER_LOG,
        }
    }
}

impl From<EventLogType> for u8 {
    fn from(value: EventLogType) -> Self {
        (&value).into()
    }
}

/// Encode an event into a record.
trait IntoRecord {
    /// Encode an event into a record.
    async fn into_record(
        &self,
        time: Option<UtcDateTime>,
        last_commit: Option<CommitHash>,
    ) -> Result<EventRecord>;
}

impl<'a, T> IntoRecord for &'a T
where
    T: Default + Encodable + Decodable + Send + Sync,
{
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
