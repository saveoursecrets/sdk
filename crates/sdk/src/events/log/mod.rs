//! Event log types and traits.
use crate::{
    commit::CommitHash, decode, formats::EventLogRecord, Result, UtcDateTime,
};
use binary_stream::futures::Decodable;

mod file;
mod reducer;

#[cfg(feature = "device")]
pub use file::DeviceEventLog;

#[cfg(feature = "device")]
pub use reducer::DeviceReducer;

#[cfg(feature = "files")]
pub use file::FileEventLog;

#[cfg(feature = "files")]
pub use reducer::FileReducer;

pub use file::{
    AccountEventLog, DiscData, DiscEventLog, DiscLog, EventLogExt,
    FolderEventLog, MemoryData, MemoryEventLog, MemoryFolderLog, MemoryLog,
};
pub use reducer::FolderReducer;

/// Record for a row in the event log.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct EventRecord(
    pub(crate) UtcDateTime,
    pub(crate) CommitHash,
    pub(crate) CommitHash,
    pub(crate) Vec<u8>,
);

impl EventRecord {
    /// Date and time the record was created.
    pub fn time(&self) -> &UtcDateTime {
        &self.0
    }

    /// Last commit hash for the record.
    pub fn last_commit(&self) -> &CommitHash {
        &self.1
    }

    /// Commit hash for the record.
    pub fn commit(&self) -> &CommitHash {
        &self.2
    }

    /// Record event bytes.
    pub fn event_bytes(&self) -> &[u8] {
        self.3.as_slice()
    }

    /// Size of the event buffer.
    pub fn size(&self) -> usize {
        self.3.len()
    }

    /// Decode this event record.
    pub async fn decode_event<T: Default + Decodable>(&self) -> Result<T> {
        decode(&self.3).await
    }
}

impl From<(EventLogRecord, Vec<u8>)> for EventRecord {
    fn from(value: (EventLogRecord, Vec<u8>)) -> Self {
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
    use std::path::PathBuf;

    use uuid::Uuid;

    use super::file::*;
    use crate::{
        commit::{CommitHash, CommitTree, Comparison},
        encode,
        events::WriteEvent,
        vault::{secret::SecretId, Vault, VaultCommit, VaultEntry},
        vfs,
    };

    const MOCK_LOG: &str = "target/mock-event-log-standalone.events";

    async fn mock_secret<'a>() -> Result<(SecretId, VaultCommit)> {
        let id = Uuid::new_v4();
        let entry = VaultEntry(Default::default(), Default::default());
        let buffer = encode(&entry).await?;
        let commit = CommitHash(CommitTree::hash(&buffer));
        let result = VaultCommit(commit, entry);
        Ok((id, result))
    }

    async fn mock_event_log_standalone() -> Result<(FolderEventLog, SecretId)>
    {
        let path = PathBuf::from(MOCK_LOG);
        if vfs::try_exists(&path).await? {
            vfs::remove_file(&path).await?;
        }

        let mut vault: Vault = Default::default();
        vault.set_name(String::from("Standalone vault"));
        let vault_buffer = encode(&vault).await?;

        let (id, data) = mock_secret().await?;

        // Create a simple event log
        let mut server = FolderEventLog::new(path).await?;
        server
            .apply(vec![
                &WriteEvent::CreateVault(vault_buffer),
                &WriteEvent::CreateSecret(id, data),
            ])
            .await?;

        Ok((server, id))
    }

    async fn mock_event_log_server_client(
    ) -> Result<(FolderEventLog, FolderEventLog, SecretId)> {
        // Required for CI which is setting the current
        // working directory to the workspace member rather
        // than using the top-level working directory
        if !vfs::try_exists("target").await? {
            vfs::create_dir("target").await?;
        }

        let server_file =
            PathBuf::from("target/mock-event-log-server.event_log");
        let client_file =
            PathBuf::from("target/mock-event-log-client.event_log");
        if vfs::try_exists(&server_file).await? {
            let _ = vfs::remove_file(&server_file).await;
        }
        if vfs::try_exists(&client_file).await? {
            let _ = vfs::remove_file(&client_file).await;
        }

        let vault: Vault = Default::default();
        let vault_buffer = encode(&vault).await?;

        let (id, data) = mock_secret().await?;

        // Create a simple event log
        let mut server = FolderEventLog::new(&server_file).await?;
        server
            .apply(vec![
                &WriteEvent::CreateVault(vault_buffer),
                &WriteEvent::CreateSecret(id, data),
            ])
            .await?;

        // Duplicate the server events on the client
        let mut client = FolderEventLog::new(&client_file).await?;
        let mut it = server.iter(false).await?;
        while let Some(record) = it.next().await? {
            let event = server.decode_event(&record).await?;
            client.apply(vec![&event]).await?;
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
        server.apply(vec![&WriteEvent::DeleteSecret(id)]).await?;

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
    async fn event_log_file_load() -> Result<()> {
        mock_event_log_standalone().await?;
        let path = PathBuf::from(MOCK_LOG);
        let event_log = FolderEventLog::new(path).await?;
        let mut it = event_log.iter(false).await?;
        while let Some(record) = it.next().await? {
            let _event = event_log.decode_event(&record).await?;
        }

        Ok(())
    }
}