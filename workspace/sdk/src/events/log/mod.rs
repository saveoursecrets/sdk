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
        events::WriteEvent,
        vault::{secret::SecretId, Vault, VaultCommit, VaultEntry},
        vfs,
    };

    const MOCK_LOG: &str = "target/mock-event-log-standalone.sos";

    async fn mock_secret<'a>() -> Result<(SecretId, Cow<'a, VaultCommit>)> {
        let id = Uuid::new_v4();
        let entry = VaultEntry(Default::default(), Default::default());
        let buffer = encode(&entry).await?;
        let commit = CommitHash(CommitTree::hash(&buffer));
        let result = VaultCommit(commit, entry);
        Ok((id, Cow::Owned(result)))
    }

    async fn mock_event_log_standalone() -> Result<(EventLogFile, SecretId)> {
        let path = PathBuf::from(MOCK_LOG);
        if vfs::try_exists(&path).await? {
            vfs::remove_file(&path).await?;
        }

        let mut vault: Vault = Default::default();
        vault.set_name(String::from("Standalone vault"));
        let vault_buffer = encode(&vault).await?;

        let (id, data) = mock_secret().await?;

        // Create a simple event log
        let mut server = EventLogFile::new(path).await?;
        server
            .apply(
                vec![
                    WriteEvent::CreateVault(Cow::Owned(vault_buffer)),
                    WriteEvent::CreateSecret(id, data),
                ],
                None,
            )
            .await?;

        Ok((server, id))
    }

    async fn mock_event_log_server_client(
    ) -> Result<(EventLogFile, EventLogFile, SecretId)> {
        let server_file =
            PathBuf::from("target/mock-event-log-server.event_log");
        let client_file =
            PathBuf::from("target/mock-event-log-client.event_log");
        let _ = vfs::remove_file(&server_file).await;
        let _ = vfs::remove_file(&client_file).await;

        let vault: Vault = Default::default();
        let vault_buffer = encode(&vault).await?;

        let (id, data) = mock_secret().await?;

        // Create a simple event log
        let mut server = EventLogFile::new(&server_file).await?;
        server
            .apply(
                vec![
                    WriteEvent::CreateVault(Cow::Owned(vault_buffer)),
                    WriteEvent::CreateSecret(id, data),
                ],
                None,
            )
            .await?;

        // Duplicate the server events on the client
        let mut client = EventLogFile::new(&client_file).await?;
        let mut it = server.iter().await?;
        while let Some(record) = it.next_entry().await? {
            let event = server.event_data(&record).await?;
            client.append_event(event).await?;
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
        let (mut server, client, id) = mock_event_log_server_client().await?;

        // Add another event to the server from another client.
        server.append_event(WriteEvent::DeleteSecret(id)).await?;

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
        let (standalone, _) = mock_event_log_standalone().await?;
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
        let _ = vfs::remove_file(&partial).await?;

        let (mut server, client, id) = mock_event_log_server_client().await?;

        // Add another event to the server from another client.
        server.append_event(WriteEvent::DeleteSecret(id)).await?;

        // Get the last record for our assertion
        let record = server.iter().await?.rev().next_entry().await?.unwrap();

        let proof = client.tree().head()?;

        let comparison = server.tree().compare(&proof)?;

        if let Comparison::Contains(indices, leaves) = comparison {
            assert_eq!(vec![1], indices);
            let leaf = leaves.first().unwrap();
            if let Some(buffer) = server.diff(*leaf).await? {
                let mut partial_log = EventLogFile::new(&partial).await?;
                partial_log.write_buffer(&buffer).await?;
                let mut records = Vec::new();
                let mut it = partial_log.iter().await?;
                while let Some(record) = it.next_entry().await? {
                    records.push(record);
                }

                assert_eq!(1, records.len());
                if let Some(diff_record) = records.get(0) {
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

    #[tokio::test]
    #[serial]
    async fn event_log_file_load() -> Result<()> {
        mock_event_log_standalone().await?;
        let path = PathBuf::from(MOCK_LOG);
        let event_log = EventLogFile::new(path).await?;
        let mut it = event_log.iter().await?;
        while let Some(record) = it.next_entry().await? {
            let _event = event_log.event_data(&record).await?;
        }

        Ok(())
    }
}
