//! Write ahead log types and traits.
use crate::{
    commit_tree::{hash, CommitTree},
    events::WalEvent,
    timestamp::Timestamp,
    CommitHash, Result,
};
use std::path::{Path, PathBuf};

use binary_stream::{
    BinaryReader, BinaryResult, BinaryWriter, Decode, Encode, SeekStream,
};

#[cfg(not(target_arch = "wasm32"))]
pub mod file;

pub mod memory;
pub mod reducer;
pub mod snapshot;

/// Trait for implementations that provide access to a write-ahead log (WAL).
pub trait WalProvider {
    /// The item yielded by the iterator implementation.
    type Item: WalItem;
    /// Partial data yielded after an iterator item until
    /// the end of the log.
    type Partial;

    /// Get a diff of the records after the record with the
    /// given commit hash.
    fn diff(&self, commit: [u8; 32]) -> Result<Option<Self::Partial>> {
        let it = self.iter()?.rev();
        for record in it {
            let record = record?;
            if record.commit() == commit {
                return Ok(Some(self.tail(record)?));
            }
        }
        Ok(None)
    }

    /// Get the last commit hash.
    fn last_commit(&self) -> Result<Option<CommitHash>> {
        let mut it = self.iter()?;
        if let Some(record) = it.next_back() {
            let record = record?;
            let buffer = self.read_buffer(&record)?;
            let last_record_hash = hash(&buffer);
            Ok(Some(CommitHash(last_record_hash)))
        } else {
            Ok(None)
        }
    }

    /// Create a new WAL provider.
    fn new<P: AsRef<Path>>(path: P) -> Result<Self>
    where
        Self: Sized;

    /// Get a copy of this WAL compacted.
    fn compact(&self) -> Result<(Self, u64, u64)>
    where
        Self: Sized;

    /// Replace this WAL with the contents of the buffer.
    ///
    /// The buffer should start with the WAL identity bytes.
    fn write_buffer(&mut self, buffer: Vec<u8>) -> Result<()>;

    /// Append the buffer to the contents of this WAL.
    ///
    /// The buffer should start with the WAL identity bytes.
    fn append_buffer(&mut self, buffer: Vec<u8>) -> Result<()>;

    /// Get the path for this provider.
    fn path(&self) -> &PathBuf;

    /// Read or encode the bytes for the item.
    fn read_buffer(&self, record: &Self::Item) -> Result<Vec<u8>>;

    /// Get the tail after the given item until the end of the log.
    fn tail(&self, item: Self::Item) -> Result<Self::Partial>;

    /// Append a collection of events and commit the tree hashes
    /// only if all the events were successfully persisted.
    ///
    /// If any events fail this function will rollback the
    /// WAL to it's previous state.
    fn apply(
        &mut self,
        events: Vec<WalEvent<'_>>,
        expect: Option<CommitHash>,
    ) -> Result<Vec<CommitHash>>;

    /// Append a log event to the write ahead log and commit
    /// the hash to the commit tree.
    fn append_event(&mut self, event: WalEvent<'_>) -> Result<CommitHash>;

    /// Read the event data from an item.
    fn event_data(&self, item: &Self::Item) -> Result<WalEvent<'_>>;

    /// Get the commit tree for the log records.
    fn tree(&self) -> &CommitTree;

    /// Load any cached data into the WAL implementation to build a commit tree in memory.
    fn load_tree(&mut self) -> Result<()>;

    /// Clear all events from this WAL.
    fn clear(&mut self) -> Result<()>;

    /// Get an iterator of the log records.
    fn iter(
        &self,
    ) -> Result<Box<dyn DoubleEndedIterator<Item = Result<Self::Item>> + '_>>;
}

/// Trait for items yielded by the iterator.
pub trait WalItem: std::fmt::Debug {
    /// Get the commit hash for the previous row.
    fn last_commit(&self) -> [u8; 32];

    /// Get the commit hash for the item.
    fn commit(&self) -> [u8; 32];

    /// Get the time for the log record.
    fn time(&self) -> &Timestamp;
}

/// Record for a row in the write ahead log.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct WalRecord(Timestamp, CommitHash, CommitHash, pub Vec<u8>);

impl Encode for WalRecord {
    fn encode(&self, writer: &mut BinaryWriter) -> BinaryResult<()> {
        // Prepare the bytes for the row length
        let size_pos = writer.tell()?;
        writer.write_u32(0)?;

        // Encode the time component
        self.0.encode(&mut *writer)?;

        // Write the previous commit hash bytes
        writer.write_bytes(self.1.as_ref())?;

        // Write the commit hash bytes
        writer.write_bytes(self.2.as_ref())?;

        // FIXME: ensure the buffer size does not exceed u32

        // Write the data bytes
        writer.write_u32(self.3.len() as u32)?;
        writer.write_bytes(&self.3)?;

        // Backtrack to size_pos and write new length
        let row_pos = writer.tell()?;
        let row_len = row_pos - (size_pos + 4);
        writer.seek(size_pos)?;
        writer.write_u32(row_len as u32)?;
        writer.seek(row_pos)?;

        // Write out the row len at the end of the record too
        // so we can support double ended iteration
        writer.write_u32(row_len as u32)?;

        Ok(())
    }
}

impl Decode for WalRecord {
    fn decode(&mut self, reader: &mut BinaryReader) -> BinaryResult<()> {
        // Read in the row length
        let _ = reader.read_u32()?;

        // Decode the time component
        let mut time: Timestamp = Default::default();
        time.decode(&mut *reader)?;

        // Read the hash bytes
        let previous: [u8; 32] =
            reader.read_bytes(32)?.as_slice().try_into()?;
        let commit: [u8; 32] =
            reader.read_bytes(32)?.as_slice().try_into()?;

        // Read the data bytes
        let length = reader.read_u32()?;
        let buffer = reader.read_bytes(length as usize)?;

        self.0 = time;
        self.1 = CommitHash(previous);
        self.2 = CommitHash(commit);
        self.3 = buffer;

        // Read in the row length appended to the end of the record
        let _ = reader.read_u32()?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use anyhow::Result;
    use std::borrow::Cow;
    use uuid::Uuid;

    use super::{memory::*, *};
    use crate::{
        commit_tree::{hash, Comparison},
        encode,
        events::WalEvent,
        secret::SecretId,
        vault::{Vault, VaultCommit, VaultEntry},
        CommitHash,
    };

    fn mock_secret<'a>() -> Result<(SecretId, Cow<'a, VaultCommit>)> {
        let id = Uuid::new_v4();
        let entry = VaultEntry(Default::default(), Default::default());
        let buffer = encode(&entry)?;
        let commit = CommitHash(hash(&buffer));
        let result = VaultCommit(commit, entry);
        Ok((id, Cow::Owned(result)))
    }

    fn mock_wal_standalone() -> Result<(WalMemory, SecretId)> {
        let mut vault: Vault = Default::default();
        vault.set_name(String::from("Standalone vault"));
        let vault_buffer = encode(&vault)?;

        let (id, data) = mock_secret()?;

        // Create a simple WAL
        let mut server: WalMemory = Default::default();
        server.apply(
            vec![
                WalEvent::CreateVault(Cow::Owned(vault_buffer)),
                WalEvent::CreateSecret(id, data),
            ],
            None,
        )?;

        Ok((server, id))
    }

    fn mock_wal_server_client() -> Result<(WalMemory, WalMemory, SecretId)> {
        let vault: Vault = Default::default();
        let vault_buffer = encode(&vault)?;

        let (id, data) = mock_secret()?;

        // Create a simple WAL
        let mut server: WalMemory = Default::default();
        server.apply(
            vec![
                WalEvent::CreateVault(Cow::Owned(vault_buffer)),
                WalEvent::CreateSecret(id, data),
            ],
            None,
        )?;

        // Duplicate the server events on the client
        let mut client: WalMemory = Default::default();
        for record in server.iter()? {
            let record = record?;
            let event = server.event_data(&record)?;
            client.append_event(event)?;
        }

        let proof = client.tree().head()?;
        let comparison = server.tree().compare(proof)?;
        assert_eq!(Comparison::Equal, comparison);

        assert_eq!(server.tree().len(), client.tree().len());
        Ok((server, client, id))
    }

    #[test]
    fn wal_compare() -> Result<()> {
        let (mut server, client, id) = mock_wal_server_client()?;

        // Add another event to the server from another client.
        server.append_event(WalEvent::DeleteSecret(id))?;

        // Check that the server contains the client proof
        let proof = client.tree().head()?;
        let comparison = server.tree().compare(proof)?;

        let matched = if let Comparison::Contains(indices, _) = comparison {
            indices == vec![1]
        } else {
            false
        };
        assert!(matched);

        // Verify that the server root is not contained by the client.
        let proof = server.tree().head()?;
        let comparison = client.tree().compare(proof)?;
        assert_eq!(Comparison::Unknown, comparison);

        // A completely different tree should also be unknown to the server.
        //
        // This can happen if a client compacts its WAL which would create
        // a new commit tree.
        let (standalone, _) = mock_wal_standalone()?;
        let proof = standalone.tree().head()?;
        let comparison = server.tree().compare(proof)?;
        assert_eq!(Comparison::Unknown, comparison);

        Ok(())
    }

    #[test]
    fn wal_diff() -> Result<()> {
        let (mut server, client, id) = mock_wal_server_client()?;

        // Add another event to the server from another client.
        server.append_event(WalEvent::DeleteSecret(id))?;

        // Get the last record for our assertion
        let record = server.iter()?.next_back().unwrap()?;

        let proof = client.tree().head()?;

        let comparison = server.tree().compare(proof)?;

        if let Comparison::Contains(indices, leaves) = comparison {
            assert_eq!(vec![1], indices);
            let leaf = leaves.get(0).unwrap();
            if let Some(records) = server.diff(*leaf)? {
                assert_eq!(1, records.len());
                assert_eq!(&record, records.get(0).unwrap());
            } else {
                panic!("expected records from diff result");
            }
        } else {
            panic!("expected comparison contains variant");
        }

        Ok(())
    }
}
