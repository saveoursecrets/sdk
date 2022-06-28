//! Write ahead log types and traits.
use crate::{
    commit_tree::CommitTree, events::WalEvent, timestamp::Timestamp,
    vault::CommitHash, Result,
};
use std::ops::Range;

use serde_binary::{
    binary_rw::SeekStream, Decode, Deserializer, Encode,
    Result as BinaryResult, Serializer,
};

pub mod file;
pub mod memory;
pub mod reducer;

/// Trait for implementations that provide access to a write-ahead log (WAL).
pub trait WalProvider {
    /// The item yielded by the iterator implementation.
    type Item: WalItem;
    /// Partial data yielded after an iterator item until
    /// the end of the log.
    type Partial;

    /// Get the tail after the given item until the end of the log.
    fn tail(&self, item: Self::Item) -> Result<Self::Partial>;

    /// Append a log event to the write ahead log.
    fn append_event(&mut self, log_event: WalEvent<'_>)
        -> Result<CommitHash>;

    /// Read the event data from an item.
    fn event_data(&self, item: Self::Item) -> Result<WalEvent<'_>>;

    /// Get the commit tree for the log records.
    fn tree(&self) -> &CommitTree;

    /// Get an iterator of the log records.
    fn iter(
        &self,
    ) -> Result<Box<dyn DoubleEndedIterator<Item = Result<Self::Item>> + '_>>;
}

/// Trait for items yielded by the iterator.
pub trait WalItem: std::fmt::Debug {
    /// Get an offset for the item.
    ///
    /// May be a byte offset or an index depending
    /// upon the implmentation.
    fn offset(&self) -> &Range<usize>;

    /// Get the commit hash for the item.
    fn commit(&self) -> [u8; 32];

    /// Get the time for the log record.
    fn time(&self) -> &Timestamp;
}

/// Record for a row in the write ahead log.
#[derive(Debug, Clone)]
pub struct WalRecord(Timestamp, CommitHash, pub Vec<u8>);

impl Encode for WalRecord {
    fn encode(&self, ser: &mut Serializer) -> BinaryResult<()> {
        // Prepare the bytes for the row length
        let size_pos = ser.writer.tell()?;
        ser.writer.write_u32(0)?;

        // Encode the time component
        self.0.encode(&mut *ser)?;

        // Write the commit hash bytes
        ser.writer.write_bytes(self.1.as_ref())?;

        // FIXME: ensure the buffer size does not exceed u32

        // Write the data bytes
        ser.writer.write_u32(self.2.len() as u32)?;
        ser.writer.write_bytes(&self.2)?;

        // Backtrack to size_pos and write new length
        let row_pos = ser.writer.tell()?;
        let row_len = row_pos - (size_pos + 4);
        ser.writer.seek(size_pos)?;
        ser.writer.write_u32(row_len as u32)?;
        ser.writer.seek(row_pos)?;

        // Write out the row len at the end of the record too
        // so we can support double ended iteration
        ser.writer.write_u32(row_len as u32)?;

        Ok(())
    }
}

impl Decode for WalRecord {
    fn decode(&mut self, de: &mut Deserializer) -> BinaryResult<()> {
        // Read in the row length
        let _ = de.reader.read_u32()?;

        // Decode the time component
        let mut time: Timestamp = Default::default();
        time.decode(&mut *de)?;

        // Read the hash bytes
        let hash_bytes: [u8; 32] =
            de.reader.read_bytes(32)?.as_slice().try_into()?;

        // Read the data bytes
        let length = de.reader.read_u32()?;
        let buffer = de.reader.read_bytes(length as usize)?;

        self.0 = time;
        self.1 = CommitHash(hash_bytes);
        self.2 = buffer;

        // Read in the row length appended to the end of the record
        let _ = de.reader.read_u32()?;

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
        crypto::AeadPack,
        events::WalEvent,
        secret::SecretId,
        vault::{encode, CommitHash, Vault, VaultCommit, VaultEntry},
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
        let mut server = WalMemory::new();
        server
            .append_event(WalEvent::CreateVault(Cow::Owned(vault_buffer)))?;
        server.append_event(WalEvent::CreateSecret(id.clone(), data))?;

        Ok((server, id))
    }

    fn mock_wal_server_client() -> Result<(WalMemory, WalMemory, SecretId)> {
        let vault: Vault = Default::default();
        let vault_buffer = encode(&vault)?;

        let (id, data) = mock_secret()?;

        // Create a simple WAL
        let mut server = WalMemory::new();
        server
            .append_event(WalEvent::CreateVault(Cow::Owned(vault_buffer)))?;
        server.append_event(WalEvent::CreateSecret(id.clone(), data))?;

        // Duplicate the server events on the client
        let mut client = WalMemory::new();
        for record in server.iter()? {
            let record = record?;
            let event = server.event_data(record)?;
            client.append_event(event)?;
        }

        let leaf_indices = vec![client.tree().len() - 1];
        let proof = client.tree().proof(&leaf_indices);
        let comparison = server
            .tree()
            .compare(client.tree().root().unwrap(), proof)?;
        assert_eq!(Comparison::Equal, comparison);

        assert_eq!(server.tree().len(), client.tree().len());
        Ok((server, client, id))
    }

    #[test]
    fn wal_compare_exists() -> Result<()> {
        let (mut server, client, id) = mock_wal_server_client()?;

        // Add another event to the server from another client.
        server.append_event(WalEvent::DeleteSecret(id.clone()))?;

        /// Check that the server contains the client proof
        let leaf_indices = vec![client.tree().len() - 1];
        let proof = client.tree().proof(&leaf_indices);
        let comparison = server
            .tree()
            .compare(client.tree().root().unwrap(), proof)?;

        let matched = if let Comparison::Contains(index, _) = comparison {
            index == 1
        } else {
            false
        };
        assert!(matched);

        // Verify that the server root is not contained by the client.
        let leaf_indices = vec![server.tree().len() - 1];
        let proof = server.tree().proof(&leaf_indices);
        let comparison = client
            .tree()
            .compare(server.tree().root().unwrap(), proof)?;
        assert_eq!(Comparison::Unknown, comparison);

        // A completely different tree should also be unknown to the server.
        //
        // This can happen if a client compacts its WAL which would create
        // a completely new commit tree.
        let (standalone, _) = mock_wal_standalone()?;
        let leaf_indices = vec![standalone.tree().len() - 1];
        let proof = standalone.tree().proof(&leaf_indices);
        let comparison = server
            .tree()
            .compare(standalone.tree().root().unwrap(), proof)?;
        assert_eq!(Comparison::Unknown, comparison);

        Ok(())
    }
}
