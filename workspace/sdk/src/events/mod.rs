//! Log and sync events.

use crate::{Error, Result};

mod audit;
mod change;
mod event;
mod log;
mod read;
mod types;
mod write;

pub use self::log::{EventLogFile, EventRecord, EventReducer};
pub use audit::{
    AuditData, AuditEvent, AuditLogFile, AuditProvider, LogFlags,
};
pub use change::{ChangeAction, ChangeEvent, ChangeNotification};
pub use event::Event;
pub use read::ReadEvent;
pub use types::EventKind;
pub use write::WriteEvent;

/// Patch wraps a changeset of events to be sent across the network.
#[derive(Clone, Debug, Default)]
pub struct Patch(pub Vec<EventRecord>);

impl Patch {
    /// Convert this patch into a collection of events.
    pub async fn into_events(&self) -> Result<Vec<WriteEvent<'static>>> {
        let mut events = Vec::new();
        for record in &self.0 {
            let event = record.decode_event().await?;
            events.push(event);
        }
        Ok(events)
    }
}
