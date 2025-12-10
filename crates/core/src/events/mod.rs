//! Events represent changes to accounts, folders and files.
//!
//! Events may be appended to *event log* files for persistence.
//!
//! Event logs maintain an in-memory merkle tree of commits to
//! enable syncing of data between devices.
//!
//! They are also used for some read events to maintain
//! an audit trail of actions.

mod account;
mod change;
mod device;
mod event;
mod event_kind;
mod event_log;
#[cfg(feature = "files")]
mod file;
pub mod patch;
mod read;
mod record;
mod write;

pub use account::AccountEvent;
pub use change::{LocalChangeEvent, changes_feed};
pub use device::DeviceEvent;
pub use event::Event;
pub use event_kind::EventKind;
pub use event_log::EventLog;
#[cfg(feature = "files")]
pub use file::FileEvent;
pub use read::ReadEvent;
pub use record::EventRecord;
pub use write::WriteEvent;

use serde::{Deserialize, Serialize};

/// Types of event logs.
#[derive(Serialize, Deserialize, Debug, Copy, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EventLogType {
    /// Identity folder event log.
    Identity,
    /// Account event log.
    Account,
    /// Device event log.
    Device,
    /// Files event log.
    #[cfg(feature = "files")]
    Files,
    /// Folder event log.
    Folder(crate::VaultId),
}

/// Trait for events that can be written to an event log.
pub trait LogEvent {
    /// Get the event kind for this event.
    fn event_kind(&self) -> EventKind;
}
