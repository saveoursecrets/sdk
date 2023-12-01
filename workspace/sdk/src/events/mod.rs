//! Log and sync events.

use crate::Result;
use binary_stream::futures::Decodable;

mod audit;
mod change;
mod event;
mod file;
mod log;
mod read;
mod types;
mod write;

pub use self::log::{
    AccountEventLog, EventLogFile, EventRecord, EventReducer,
    FolderEventLog,
};

#[cfg(feature = "files")]
pub use self::log::FileEventLog;

pub use audit::{
    AuditData, AuditEvent, AuditLogFile, AuditProvider, LogFlags,
};
pub use change::{ChangeAction, ChangeEvent, ChangeNotification};
pub use event::{AccountEvent, Event};
pub use file::FileEvent;
pub use read::ReadEvent;
pub use types::EventKind;
pub use write::WriteEvent;

/// Trait for events that can be written to an event log..
pub trait LogEvent {
    /// Get the event kind for this event.
    fn event_kind(&self) -> EventKind;
}

/// Patch wraps a changeset of events to be sent across the network.
#[derive(Clone, Debug, Default)]
pub struct Patch(pub Vec<EventRecord>);

impl Patch {
    /// Convert this patch into a collection of events.
    pub async fn into_events<T: Default + Decodable>(
        &self,
    ) -> Result<Vec<T>> {
        let mut events = Vec::new();
        for record in &self.0 {
            let event = record.decode_event::<T>().await?;
            events.push(event);
        }
        Ok(events)
    }
}
