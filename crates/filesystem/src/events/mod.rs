//! Events represent changes to accounts, folders and files.
//!
//! Events may be appended to *event log* files for persistence.
//!
//! Event logs maintain an in-memory merkle tree of commits to
//! enable syncing of data between devices.
//!
//! They are also used for some read events to maintain
//! an audit trail of actions.

use crate::Result;
use async_trait::async_trait;
use binary_stream::futures::{Decodable, Encodable};
use sos_core::{
    commit::{CommitHash, CommitTree},
    encode,
};

mod log;

pub use self::log::{
    patch::*, AccountEventLog, DiscData, DiscEventLog, DiscLog, EventLogExt,
    EventRecord, FolderEventLog, MemoryData, MemoryEventLog, MemoryFolderLog,
    MemoryLog,
};

pub use self::log::{DeviceEventLog, DeviceReducer};

#[cfg(feature = "files")]
pub use self::log::FileEventLog;

#[cfg(feature = "files")]
pub use self::log::FileReducer;

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
        Ok(EventRecord::new(
            Default::default(),
            Default::default(),
            commit,
            bytes,
        ))
    }
}
