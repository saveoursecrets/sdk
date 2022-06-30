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
use std::ops::Range;

use super::{WalItem, WalProvider, WalRecord};

/// Wrapper for a WAL record that includes an index offset.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WalMemoryRecord(Range<usize>, WalRecord);

impl WalItem for WalMemoryRecord {
    fn offset(&self) -> &Range<usize> {
        &self.0
    }

    fn commit(&self) -> [u8; 32] {
        self.1 .1 .0
    }

    fn time(&self) -> &Timestamp {
        &self.1 .0
    }
}

/// A write ahead log that stores records in memory.
#[derive(Default)]
pub struct WalMemory {
    records: Vec<WalMemoryRecord>,
    tree: CommitTree,
}

impl WalMemory {
    /// Create a new write ahead log memory store.
    pub fn new() -> Self {
        Default::default()
    }

    fn encode_event(
        &self,
        event: WalEvent<'_>,
        offset: usize,
    ) -> Result<(CommitHash, WalMemoryRecord)> {
        let time: Timestamp = Default::default();
        let bytes = encode(&event)?;
        let commit = CommitHash(hash(&bytes));
        Ok((
            commit,
            WalMemoryRecord(offset..offset, WalRecord(time, commit, bytes)),
        ))
    }
}

impl WalProvider for WalMemory {
    type Item = WalMemoryRecord;
    type Partial = Vec<WalMemoryRecord>;

    fn tail(&self, item: Self::Item) -> Result<Self::Partial> {
        let mut partial = Vec::new();
        let index = item.0.start + 1;
        if index < self.records.len() {
            let items = &self.records[index..self.records.len()];
            partial.extend_from_slice(items);
        }
        Ok(partial)
    }

    fn tree(&self) -> &CommitTree {
        &self.tree
    }

    fn apply(
        &mut self,
        events: Vec<WalEvent<'_>>,
    ) -> Result<Vec<CommitHash>> {
        let mut records = Vec::new();
        let mut commits = Vec::new();
        let offset = self.records.len();
        for (index, event) in events.into_iter().enumerate() {
            let (commit, record) =
                self.encode_event(event, offset + index)?;
            commits.push(commit);
            records.push(record);
        }

        let mut hashes =
            commits.iter().map(|c| *c.as_ref()).collect::<Vec<_>>();

        self.records.extend_from_slice(&records);
        self.tree.append(&mut hashes);
        self.tree.commit();
        Ok(commits)
    }

    fn append_event(&mut self, event: WalEvent<'_>) -> Result<CommitHash> {
        let (commit, record) =
            self.encode_event(event, self.records.len())?;
        self.records.push(record);
        self.tree.insert(*commit.as_ref());
        self.tree.commit();
        Ok(commit)
    }

    fn event_data(&self, item: Self::Item) -> Result<WalEvent<'_>> {
        let event: WalEvent = decode(&item.1 .2)?;
        Ok(event)
    }

    fn load_tree(&mut self) -> Result<()> {
        Ok(())
    }

    fn iter(
        &self,
    ) -> Result<Box<dyn DoubleEndedIterator<Item = Result<Self::Item>> + '_>>
    {
        Ok(Box::new(self.records.iter().cloned().map(|v| Ok(v))))
    }
}
