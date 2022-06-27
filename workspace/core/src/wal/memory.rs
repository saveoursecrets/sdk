//! Memory backed WAL provider implementation.
//!
//! Clients that do not have the ability to write to disc
//! can use this for caching a WAL.
//!
//! Whilst it is possible for this iterator implementation to
//! return a reference (`&'a WalRecord`) it requires adding a
//! lifetime to the `WalProvider` trait which cascades all the
//! way down to the server `Backend` and associated `State` and
//! causes numerous lifetime issues in the server code so for
//! the moment we just clone the records during iteration.
use crate::{
    commit_tree::{hash, CommitTree},
    decode, encode,
    events::WalEvent,
    timestamp::Timestamp,
    vault::CommitHash,
    Result,
};

use super::{WalProvider, WalRecord};

/// A write ahead log that stores records in memory.
#[derive(Default)]
pub struct WalMemory {
    records: Vec<WalRecord>,
    tree: CommitTree,
}

impl WalMemory {
    /// Create a new write ahead log memory store.
    pub fn new() -> Self {
        Default::default()
    }
}

impl WalProvider for WalMemory {
    type Item = WalRecord;

    fn tree(&self) -> &CommitTree {
        &self.tree
    }

    fn append_event(
        &mut self,
        log_event: WalEvent<'_>,
    ) -> Result<CommitHash> {
        let log_time: Timestamp = Default::default();
        let log_bytes = encode(&log_event)?;
        let hash_bytes = hash(&log_bytes);
        self.tree.insert(hash_bytes);
        let log_commit = CommitHash(hash_bytes);
        let log_record = WalRecord(log_time, log_commit, log_bytes);
        self.records.push(log_record);
        self.tree.commit();
        Ok(log_commit)
    }

    fn event_data(&self, item: Self::Item) -> Result<WalEvent<'_>> {
        let event: WalEvent = decode(&item.2)?;
        Ok(event)
    }

    fn iter(
        &self,
    ) -> Result<Box<dyn DoubleEndedIterator<Item = Result<Self::Item>> + '_>>
    {
        Ok(Box::new(self.records.iter().cloned().map(|v| Ok(v))))
    }
}
