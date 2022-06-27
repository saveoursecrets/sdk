//! Memory backed WAL provider implementation.
//!
//! Clients that do not have the ability to write to disc
//! can use this for caching a WAL.
use crate::{
    commit_tree::{hash, CommitTree},
    decode, encode,
    events::WalEvent,
    vault::CommitHash,
    Result,
};

use super::{LogRecord, LogTime, WalItem, WalProvider};

/// A write ahead log that stores records in memory.
#[derive(Default)]
pub struct WalMemory {
    records: Vec<LogRecord>,
    tree: CommitTree,
}

impl WalMemory {
    /// Create a new write ahead log memory store.
    pub fn new() -> Self {
        Default::default()
    }
}

impl WalProvider for WalMemory {
    type Item = LogRecord;

    fn tree(&self) -> &CommitTree {
        &self.tree
    }

    fn append_event(
        &mut self,
        log_event: WalEvent<'_>,
    ) -> Result<CommitHash> {
        let log_time: LogTime = Default::default();
        let log_bytes = encode(&log_event)?;
        let hash_bytes = hash(&log_bytes);
        self.tree.insert(hash_bytes);
        let log_commit = CommitHash(hash_bytes);
        let log_record = LogRecord(log_time, log_commit, log_bytes);
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
    ) -> Result<Box<dyn DoubleEndedIterator<Item = Result<Self::Item>>>> {
        // TODO: figure out how to avoid this clone without
        // TODO: getting caught up in lifetime madness
        let records = self.records.clone();
        Ok(Box::new(records.into_iter().map(|v| Ok(v))))
    }
}
