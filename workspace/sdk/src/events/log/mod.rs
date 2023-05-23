//! Write ahead log types and traits.
use crate::{
    commit::CommitHash, formats::EventLogFileRecord, timestamp::Timestamp,
};

use std::io::{Read, Seek, Write};

use binary_stream::{
    BinaryReader, BinaryResult, BinaryWriter, Decode, Encode,
};

mod file;
mod reducer;

pub use file::EventLogFile;
pub use reducer::EventReducer;

/// Record for a row in the write ahead log.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct EventRecord(Timestamp, CommitHash, CommitHash, pub Vec<u8>);

impl EventRecord {
    /// Get the time for the record.
    pub fn time(&self) -> &Timestamp {
        &self.0
    }

    /// Get the last commit hash for the record.
    pub fn last_commit(&self) -> &CommitHash {
        &self.1
    }

    /// Get the commit hash for the record.
    pub fn commit(&self) -> &CommitHash {
        &self.2
    }

    /// Get the event bytes the record.
    pub fn event_bytes(&self) -> &[u8] {
        self.3.as_slice()
    }
}

impl From<(EventLogFileRecord, Vec<u8>)> for EventRecord {
    fn from(value: (EventLogFileRecord, Vec<u8>)) -> Self {
        Self(
            value.0.time,
            CommitHash(value.0.last_commit),
            CommitHash(value.0.commit),
            value.1,
        )
    }
}

impl Encode for EventRecord {
    fn encode<W: Write + Seek>(
        &self,
        writer: &mut BinaryWriter<W>,
    ) -> BinaryResult<()> {
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

impl Decode for EventRecord {
    fn decode<R: Read + Seek>(
        &mut self,
        reader: &mut BinaryReader<R>,
    ) -> BinaryResult<()> {
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
    use serial_test::serial;
    use std::{borrow::Cow, path::PathBuf};

    use uuid::Uuid;

    use super::file::*;
    use crate::{
        commit::{CommitHash, CommitTree, Comparison},
        encode,
        events::SyncEvent,
        vault::{secret::SecretId, Vault, VaultCommit, VaultEntry},
    };

    fn mock_secret<'a>() -> Result<(SecretId, Cow<'a, VaultCommit>)> {
        let id = Uuid::new_v4();
        let entry = VaultEntry(Default::default(), Default::default());
        let buffer = encode(&entry)?;
        let commit = CommitHash(CommitTree::hash(&buffer));
        let result = VaultCommit(commit, entry);
        Ok((id, Cow::Owned(result)))
    }

    fn mock_event_log_standalone() -> Result<(EventLogFile, SecretId)> {
        let mut vault: Vault = Default::default();
        vault.set_name(String::from("Standalone vault"));
        let vault_buffer = encode(&vault)?;

        let (id, data) = mock_secret()?;

        // Create a simple event log
        let mut server =
            EventLogFile::new("target/mock-event-log-standalone.event_log")?;
        server.apply(
            vec![
                SyncEvent::CreateVault(Cow::Owned(vault_buffer)),
                SyncEvent::CreateSecret(id, data),
            ],
            None,
        )?;

        Ok((server, id))
    }

    fn mock_event_log_server_client(
    ) -> Result<(EventLogFile, EventLogFile, SecretId)> {
        let server_file =
            PathBuf::from("target/mock-event-log-server.event_log");
        let client_file =
            PathBuf::from("target/mock-event-log-client.event_log");
        if server_file.exists() {
            std::fs::remove_file(&server_file)?;
        }
        if client_file.exists() {
            std::fs::remove_file(&client_file)?;
        }

        let vault: Vault = Default::default();
        let vault_buffer = encode(&vault)?;

        let (id, data) = mock_secret()?;

        // Create a simple event log
        let mut server = EventLogFile::new(&server_file)?;
        server.apply(
            vec![
                SyncEvent::CreateVault(Cow::Owned(vault_buffer)),
                SyncEvent::CreateSecret(id, data),
            ],
            None,
        )?;

        // Duplicate the server events on the client
        let mut client = EventLogFile::new(&client_file)?;
        for record in server.iter()? {
            let record = record?;
            let event = server.event_data(&record)?;
            client.append_event(event)?;
        }

        let proof = client.tree().head()?;
        let comparison = server.tree().compare(&proof)?;
        assert_eq!(Comparison::Equal, comparison);

        assert_eq!(server.tree().len(), client.tree().len());
        Ok((server, client, id))
    }

    #[tokio::test]
    #[serial]
    async fn event_log_compare() -> Result<()> {
        let (mut server, client, id) = mock_event_log_server_client()?;

        // Add another event to the server from another client.
        server.append_event(SyncEvent::DeleteSecret(id))?;

        // Check that the server contains the client proof
        let proof = client.tree().head()?;
        let comparison = server.tree().compare(&proof)?;

        let matched = if let Comparison::Contains(indices, _) = comparison {
            indices == vec![1]
        } else {
            false
        };
        assert!(matched);

        // Verify that the server root is not contained by the client.
        let proof = server.tree().head()?;
        let comparison = client.tree().compare(&proof)?;
        assert_eq!(Comparison::Unknown, comparison);

        // A completely different tree should also be unknown to the server.
        //
        // This can happen if a client compacts its event log which would create
        // a new commit tree.
        let (standalone, _) = mock_event_log_standalone()?;
        let proof = standalone.tree().head()?;
        let comparison = server.tree().compare(&proof)?;
        assert_eq!(Comparison::Unknown, comparison);

        Ok(())
    }

    #[tokio::test]
    #[serial]
    async fn event_log_diff() -> Result<()> {
        let partial =
            PathBuf::from("target/mock-event-log-partial.event_log");
        if partial.exists() {
            std::fs::remove_file(&partial)?;
        }

        let (mut server, client, id) = mock_event_log_server_client()?;

        // Add another event to the server from another client.
        server.append_event(SyncEvent::DeleteSecret(id))?;

        // Get the last record for our assertion
        let record = server.iter()?.next_back().unwrap()?;

        let proof = client.tree().head()?;

        let comparison = server.tree().compare(&proof)?;

        if let Comparison::Contains(indices, leaves) = comparison {
            assert_eq!(vec![1], indices);
            let leaf = leaves.first().unwrap();
            if let Some(buffer) = server.diff(*leaf)? {
                let mut partial_log = EventLogFile::new(&partial)?;
                partial_log.write_buffer(&buffer).await?;
                let records: Vec<_> = partial_log.iter()?.collect();
                assert_eq!(1, records.len());
                if let Some(diff_record) = records.get(0) {
                    let diff_record = diff_record.as_ref().unwrap();
                    assert_eq!(&record, diff_record);
                } else {
                    panic!("expecting record");
                }
            } else {
                panic!("expected records from diff result");
            }
        } else {
            panic!("expected comparison contains variant");
        }

        Ok(())
    }

    #[test]
    fn event_log_file_load() -> Result<()> {
        let path =
            PathBuf::from("../../tests/fixtures/simple-vault.sos");
        let event_log = EventLogFile::new(path)?;
        let it = event_log.iter()?;
        for record in it {
            let record = record?;
            let _event = event_log.event_data(&record)?;
        }

        Ok(())
    }
}
