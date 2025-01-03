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
mod device;
mod event;
mod event_kind;
#[cfg(feature = "files")]
mod file;
mod read;
mod write;

pub use account::AccountEvent;
pub use device::DeviceEvent;
pub use event::Event;
pub use event_kind::EventKind;
#[cfg(feature = "files")]
pub use file::FileEvent;
pub use read::ReadEvent;
pub use write::WriteEvent;

/// Trait for events that can be written to an event log.
pub trait LogEvent {
    /// Get the event kind for this event.
    fn event_kind(&self) -> EventKind;
}

/*
/// Encode an event into a record.
#[async_trait]
pub trait IntoRecord {
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
        let bytes = encode(*self).await?;
        let commit = CommitHash(CommitTree::hash(&bytes));
        Ok(EventRecord(
            Default::default(),
            Default::default(),
            commit,
            bytes,
        ))
    }
}
*/
