//! Write ahead log types and traits.
use crate::{
    commit::CommitHash, formats::EventLogFileRecord, timestamp::Timestamp,
};

mod file;
mod reducer;

pub use file::EventLogFile;
pub use reducer::EventReducer;

/// Record for a row in the write ahead log.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct EventRecord(
    pub(crate) Timestamp,
    pub(crate) CommitHash,
    pub(crate) CommitHash,
    pub(crate) Vec<u8>,
);

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
        events::{Event, WriteEvent},
        vault::{secret::SecretId, Vault, VaultCommit, VaultEntry},
    };

    const MOCK_LOG: &str = "target/mock-event-log-standalone.sos";

    fn mock_secret<'a>() -> Result<(SecretId, Cow<'a, VaultCommit>)> {
        let id = Uuid::new_v4();
        let entry = VaultEntry(Default::default(), Default::default());
        let buffer = encode(&entry)?;
        let commit = CommitHash(CommitTree::hash(&buffer));
        let result = VaultCommit(commit, entry);
        Ok((id, Cow::Owned(result)))
    }

    fn mock_event_log_standalone() -> Result<(EventLogFile, SecretId)> {
        let path = PathBuf::from(MOCK_LOG);

        if path.exists() {
            std::fs::remove_file(&path)?;
        }

        let mut vault: Vault = Default::default();
        vault.set_name(String::from("Standalone vault"));
        let vault_buffer = encode(&vault)?;

        let (id, data) = mock_secret()?;

        // Create a simple event log
        let mut server =
            EventLogFile::new(MOCK_LOG)?;
        server.apply(
            vec![
                WriteEvent::CreateVault(Cow::Owned(vault_buffer)),
                WriteEvent::CreateSecret(id, data),
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
                WriteEvent::CreateVault(Cow::Owned(vault_buffer)),
                WriteEvent::CreateSecret(id, data),
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
        server.append_event(WriteEvent::DeleteSecret(id))?;

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
        server.append_event(WriteEvent::DeleteSecret(id))?;

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
        mock_event_log_standalone()?;
        let path = PathBuf::from(MOCK_LOG);
        let event_log = EventLogFile::new(path)?;
        let it = event_log.iter()?;
        for record in it {
            let record = record?;
            let _event = event_log.event_data(&record)?;
        }

        Ok(())
    }
}
