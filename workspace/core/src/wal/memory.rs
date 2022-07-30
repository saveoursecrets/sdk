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
    constants::WAL_IDENTITY,
    decode, encode,
    events::WalEvent,
    iter::{FileItem, ReadStreamIterator, WalFileRecord},
    timestamp::Timestamp,
    CommitHash, Result,
};

use binary_stream::{BinaryReader, Endian, MemoryStream};

use std::path::{Path, PathBuf};

use super::{reducer::WalReducer, WalItem, WalProvider, WalRecord};

/// Wrapper for a WAL record that includes an index offset.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WalMemoryRecord(usize, WalRecord);

impl WalItem for WalMemoryRecord {
    fn last_commit(&self) -> [u8; 32] {
        self.1 .1 .0
    }

    fn commit(&self) -> [u8; 32] {
        self.1 .2 .0
    }

    fn time(&self) -> &Timestamp {
        &self.1 .0
    }
}

/// A write ahead log that stores records in memory.
pub struct WalMemory {
    records: Vec<WalMemoryRecord>,
    tree: CommitTree,
    path: PathBuf,
}

impl Default for WalMemory {
    fn default() -> Self {
        Self {
            records: Default::default(),
            tree: Default::default(),
            path: PathBuf::from("/dev/memory"),
        }
    }
}

impl WalMemory {
    fn encode_event(
        &self,
        event: WalEvent<'_>,
        offset: usize,
    ) -> Result<(CommitHash, WalMemoryRecord)> {
        let time: Timestamp = Default::default();
        let bytes = encode(&event)?;
        let last_commit =
            self.last_commit()?.unwrap_or_else(|| CommitHash([0u8; 32]));
        let commit = CommitHash(hash(&bytes));
        Ok((
            commit,
            WalMemoryRecord(
                offset,
                WalRecord(time, last_commit, commit, bytes),
            ),
        ))
    }

    fn decode_file_records(
        &self,
        buffer: Vec<u8>,
        start: usize,
    ) -> Result<Vec<WalMemoryRecord>> {
        let mut stream: MemoryStream = buffer.clone().into();
        let mut reader = BinaryReader::new(&mut stream, Endian::Big);
        let it = ReadStreamIterator::<WalFileRecord>::new_memory(
            buffer,
            &WAL_IDENTITY,
            true,
            None,
        )?;

        let mut records = Vec::new();
        for (index, record) in it.into_iter().enumerate() {
            let record = record?;
            let event_bytes = record.read_bytes(&mut reader)?;
            let record: WalRecord = (record, event_bytes).into();
            records.push(WalMemoryRecord(start + index, record));
        }
        Ok(records)
    }
}

impl WalProvider for WalMemory {
    type Item = WalMemoryRecord;
    type Partial = Vec<WalMemoryRecord>;

    fn new<P: AsRef<Path>>(_path: P) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(Default::default())
    }

    fn compact(&self) -> Result<(Self, u64, u64)> {
        let old_size = self.records.len() as u64;

        let path = self.path().clone();

        // Get the reduced set of events
        let events = WalReducer::new().reduce(self)?.compact()?;

        // Apply them to a temporary WAL file
        let mut temp_wal = WalMemory::new(&path)?;
        temp_wal.apply(events, None)?;

        let new_size = temp_wal.records.len() as u64;

        // Need to recreate the WAL file and load the updated
        // commit tree
        Ok((temp_wal, old_size, new_size))
    }

    fn write_buffer(&mut self, buffer: Vec<u8>) -> Result<()> {
        let records = self.decode_file_records(buffer, 0)?;
        self.records = records;
        self.load_tree()?;
        Ok(())
    }

    fn append_buffer(&mut self, buffer: Vec<u8>) -> Result<()> {
        let mut records = self.decode_file_records(buffer, self.records.len())?;
        let mut commits: Vec<[u8; 32]> = records.iter()
            .map(|v| {
                let commit = *v.1.commit();
                let commit: [u8; 32] = commit.into();
                commit
            }).collect();

        self.records.append(&mut records);
        self.tree.append(&mut commits);
        self.tree.commit();

        Ok(())
    }

    fn tail(&self, item: Self::Item) -> Result<Self::Partial> {
        let mut partial = Vec::new();
        let index = item.0 + 1;
        if index < self.records.len() {
            let items = &self.records[index..self.records.len()];
            partial.extend_from_slice(items);
        }
        Ok(partial)
    }

    fn path(&self) -> &PathBuf {
        &self.path
    }

    fn tree(&self) -> &CommitTree {
        &self.tree
    }

    fn read_buffer(&self, record: &Self::Item) -> Result<Vec<u8>> {
        let buffer = encode(&record.1)?;
        Ok(buffer)
    }

    fn apply(
        &mut self,
        events: Vec<WalEvent<'_>>,
        expect: Option<CommitHash>,
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

        // Rollback to previous state if expected commit hash
        // does not match the new commit hash
        if let (Some(expected), Some(root)) = (expect, self.tree.root()) {
            let other_root: [u8; 32] = expected.into();
            if other_root != root {
                self.records.truncate(offset);
                self.tree.rollback();
            }
        }

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

    fn event_data(&self, item: &Self::Item) -> Result<WalEvent<'_>> {
        let event: WalEvent = decode(&item.1 .3)?;
        Ok(event)
    }

    fn load_tree(&mut self) -> Result<()> {
        self.tree = CommitTree::new();
        let mut commits: Vec<[u8; 32]> = self.records.iter()
            .map(|v| {
                let commit = *v.1.commit();
                let commit: [u8; 32] = commit.into();
                commit
            }).collect();

        self.tree.append(&mut commits);
        self.tree.commit();
        Ok(())
    }

    fn clear(&mut self) -> Result<()> {
        self.records = Vec::new();
        self.tree = CommitTree::new();
        Ok(())
    }

    fn iter(
        &self,
    ) -> Result<Box<dyn DoubleEndedIterator<Item = Result<Self::Item>> + '_>>
    {
        Ok(Box::new(self.records.iter().cloned().map(Ok)))
    }
}
