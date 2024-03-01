use crate::{
    commit::CommitHash,
    crypto::AeadPack,
    decode, encode,
    events::{EventLogExt, FolderEventLog, WriteEvent},
    vault::{secret::SecretId, Vault, VaultCommit},
    Error, Result,
};

use indexmap::IndexMap;

/// Reduce log events to a vault.
#[derive(Default)]
pub struct FolderReducer {
    /// Buffer for the create or last update vault event.
    vault: Option<Vec<u8>>,
    /// Last encountered vault name.
    vault_name: Option<String>,
    /// Last encountered vault meta data.
    vault_meta: Option<AeadPack>,
    /// Map of the reduced secrets.
    secrets: IndexMap<SecretId, VaultCommit>,
    /// Reduce events until a particular commit.
    until_commit: Option<CommitHash>,
}

impl FolderReducer {
    /// Create a new reducer.
    pub fn new() -> Self {
        Default::default()
    }

    /// Create a new reducer until a commit.
    pub fn new_until_commit(until: CommitHash) -> Self {
        Self {
            until_commit: Some(until),
            ..Default::default()
        }
    }

    /// Split a vault into a truncated vault and a collection
    /// of events that represent the vault content.
    ///
    /// The truncated vault represents the header of the vault and
    /// has no contents.
    pub async fn split(vault: Vault) -> Result<(Vault, Vec<WriteEvent>)> {
        let mut events = Vec::with_capacity(vault.len() + 1);
        let header = vault.header().clone();
        let head: Vault = header.into();

        let buffer = encode(&head).await?;
        events.push(WriteEvent::CreateVault(buffer));
        for (id, entry) in vault {
            events.push(WriteEvent::CreateSecret(id, entry));
        }

        Ok((head, events))
    }

    /// Reduce the events in the given event log.
    pub async fn reduce(
        mut self,
        event_log: &FolderEventLog,
    ) -> Result<FolderReducer> {
        // TODO: use event_log.stream() !

        let mut it = event_log.iter(false).await?;
        if let Some(log) = it.next().await? {
            let event = event_log.decode_event(&log).await?;

            if let WriteEvent::CreateVault(vault) = event {
                self.vault = Some(vault.clone());

                // If we are only reading until the first commit
                // hash return early.
                if let Some(until) = &self.until_commit {
                    if until.0 == log.commit() {
                        return Ok(self);
                    }
                }

                while let Some(log) = it.next().await? {
                    let event = event_log.decode_event(&log).await?;
                    match event {
                        WriteEvent::CreateVault(_) => {
                            return Err(Error::CreateEventOnlyFirst)
                        }
                        WriteEvent::SetVaultName(name) => {
                            self.vault_name = Some(name);
                        }
                        WriteEvent::SetVaultMeta(meta) => {
                            self.vault_meta = Some(meta);
                        }
                        WriteEvent::CreateSecret(id, entry) => {
                            self.secrets.insert(id, entry);
                        }
                        WriteEvent::UpdateSecret(id, entry) => {
                            self.secrets.insert(id, entry);
                        }
                        WriteEvent::DeleteSecret(id) => {
                            self.secrets.shift_remove(&id);
                        }
                        _ => {}
                    }

                    // If we are reading to a particular commit hash
                    // we are done.
                    if let Some(until) = &self.until_commit {
                        if until.0 == log.commit() {
                            break;
                        }
                    }
                }
            } else {
                return Err(Error::CreateEventMustBeFirst);
            }
        }

        Ok(self)
    }

    /// Create a series of new events that represent
    /// a compacted version of the event log.
    ///
    /// This series of events can then be appended to a
    /// new event log to create a compact version with
    /// history pruned.
    ///
    /// Note that compaction is lossy; log record
    /// timestamps are reset.
    ///
    /// The commit tree returned here will be invalid once
    /// the new series of events have been applied so callers
    /// must generate a new commit tree once the new event log has
    /// been created.
    pub async fn compact(self) -> Result<Vec<WriteEvent>> {
        if let Some(vault) = self.vault {
            let mut events = Vec::new();

            let mut vault: Vault = decode(&vault).await?;
            if let Some(name) = self.vault_name {
                vault.set_name(name);
            }

            if let Some(meta) = self.vault_meta {
                vault.header_mut().set_meta(Some(meta));
            }

            let buffer = encode(&vault).await?;
            events.push(WriteEvent::CreateVault(buffer));
            for (id, entry) in self.secrets {
                events.push(WriteEvent::CreateSecret(id, entry));
            }
            Ok(events)
        } else {
            Ok(Vec::new())
        }
    }

    /// Consume this reducer and build a vault.
    pub async fn build(self, include_secrets: bool) -> Result<Vault> {
        if let Some(vault) = self.vault {
            let mut vault: Vault = decode(&vault).await?;
            if let Some(name) = self.vault_name {
                vault.set_name(name);
            }

            if let Some(meta) = self.vault_meta {
                vault.header_mut().set_meta(Some(meta));
            }

            if include_secrets {
                for (id, entry) in self.secrets {
                    vault.insert_entry(id, entry);
                }
            }
            Ok(vault)
        } else {
            Ok(Default::default())
        }
    }
}

#[cfg(feature = "device")]
mod device {
    use crate::{
        device::TrustedDevice,
        events::{DeviceEvent, DeviceEventLog, EventLogExt},
        Result,
    };
    use futures::{pin_mut, stream::StreamExt};
    use indexmap::IndexSet;

    /// Reduce device events to a collection of devices.
    pub struct DeviceReducer<'a> {
        log: &'a DeviceEventLog,
    }

    impl<'a> DeviceReducer<'a> {
        /// Create a new device reducer.
        pub fn new(log: &'a DeviceEventLog) -> Self {
            Self { log }
        }

        /// Reduce device events to a canonical collection
        /// of trusted devices.
        pub async fn reduce(self) -> Result<IndexSet<TrustedDevice>> {
            let mut devices = IndexSet::new();

            let stream = self.log.stream(false).await;
            pin_mut!(stream);

            while let Some(event) = stream.next().await {
                let (_, event) = event?;

                match event {
                    DeviceEvent::Trust(device) => {
                        devices.insert(device);
                    }
                    DeviceEvent::Revoke(public_key) => {
                        let device = devices
                            .iter()
                            .find(|d| d.public_key() == &public_key)
                            .cloned();
                        if let Some(device) = device {
                            devices.shift_remove(&device);
                        }
                    }
                    _ => {}
                }
            }
            Ok(devices)
        }
    }
}

#[cfg(feature = "device")]
pub use device::DeviceReducer;

#[cfg(feature = "files")]
mod files {
    use crate::{
        commit::CommitHash,
        events::{EventLogExt, FileEvent, FileEventLog},
        storage::files::ExternalFile,
        Result,
    };
    use futures::{pin_mut, stream::StreamExt};
    use indexmap::IndexSet;

    /// Reduce file events to a collection of external files.
    pub struct FileReducer<'a> {
        log: &'a FileEventLog,
    }

    impl<'a> FileReducer<'a> {
        /// Create a new file reducer.
        pub fn new(log: &'a FileEventLog) -> Self {
            Self { log }
        }

        fn add_file_event(
            &self,
            event: FileEvent,
            files: &mut IndexSet<ExternalFile>,
        ) {
            match event {
                FileEvent::CreateFile(vault_id, secret_id, file_name) => {
                    files.insert(ExternalFile::new(
                        vault_id, secret_id, file_name,
                    ));
                }
                FileEvent::MoveFile { name, from, dest } => {
                    let file = ExternalFile::new(from.0, from.1, name);
                    files.shift_remove(&file);
                    files.insert(ExternalFile::new(dest.0, dest.1, name));
                }
                FileEvent::DeleteFile(vault_id, secret_id, file_name) => {
                    let file =
                        ExternalFile::new(vault_id, secret_id, file_name);
                    files.shift_remove(&file);
                }
                _ => {}
            }
        }

        /// Reduce file events to a canonical collection
        /// of external files.
        #[cfg(feature = "sync")]
        pub async fn reduce(
            self,
            from: Option<&CommitHash>,
        ) -> Result<IndexSet<ExternalFile>> {
            let mut files: IndexSet<ExternalFile> = IndexSet::new();

            // Reduce from the target commit.
            //
            // When reducing from a target commit we perform
            // a diff as this reads from the tail of the event
            // log which will be faster than scanning when there
            // are lots of file events.
            if let Some(from) = from {
                #[cfg(feature = "sync")]
                {
                    let patch = self.log.diff(Some(from)).await?;
                    let events: Vec<FileEvent> = patch.into();
                    for event in events {
                        self.add_file_event(event, &mut files);
                    }
                }

                #[cfg(not(feature = "sync"))]
                panic!("file reducer with diff requires the sync feature");
            } else {
                let stream = self.log.stream(false).await;
                pin_mut!(stream);

                while let Some(event) = stream.next().await {
                    let (_, event) = event?;
                    self.add_file_event(event, &mut files);
                }
            }

            Ok(files)
        }

        /// Reduce file events to a canonical collection
        /// of external files.
        #[cfg(not(feature = "sync"))]
        pub async fn reduce(self) -> Result<IndexSet<ExternalFile>> {
            let mut files: IndexSet<ExternalFile> = IndexSet::new();

            let stream = self.log.stream(false).await;
            pin_mut!(stream);

            while let Some(event) = stream.next().await {
                let (_, event) = event?;
                self.add_file_event(event, &mut files);
            }

            Ok(files)
        }
    }
}

#[cfg(feature = "files")]
pub use files::FileReducer;

/*
/// Reduce account events to a collection of folders.
pub struct AccountReducer<'a> {
    log: &'a mut AccountEventLog,
}

impl<'a> AccountReducer<'a> {
    /// Create a new account reducer.
    pub fn new(log: &'a mut AccountEventLog) -> Self {
        Self { log }
    }

    /// Reduce account events to a canonical collection
    /// of folders.
    pub async fn reduce(self) -> Result<HashSet<VaultId>> {
        let mut folders = HashSet::new();
        let events = self.log.diff_records(None).await?;
        for record in events {
            let event = record.decode_event::<AccountEvent>().await?;
            match event {
                AccountEvent::UpdateFolder(id, _)
                | AccountEvent::CreateFolder(id, _) => {
                    folders.insert(id);
                }
                AccountEvent::DeleteFolder(id) => {
                    folders.remove(&id);
                }
                _ => {}
            }
        }
        Ok(folders)
    }
}
*/

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        commit::CommitHash,
        crypto::PrivateKey,
        decode,
        events::{FolderEventLog, WriteEvent},
        test_utils::*,
        vault::{
            secret::{Secret, SecretId, SecretMeta},
            VaultAccess, VaultCommit, VaultEntry,
        },
    };
    use anyhow::Result;
    use secrecy::ExposeSecret;
    use tempfile::NamedTempFile;

    async fn mock_event_log_file() -> Result<(
        NamedTempFile,
        FolderEventLog,
        Vec<CommitHash>,
        PrivateKey,
        SecretId,
    )> {
        let (encryption_key, _, _) = mock_encryption_key()?;
        let (_, mut vault, buffer) = mock_vault_file().await?;

        let temp = NamedTempFile::new()?;
        let mut event_log = FolderEventLog::new(temp.path()).await?;

        let mut commits = Vec::new();

        // Create the vault
        let event = WriteEvent::CreateVault(buffer);
        commits.append(&mut event_log.apply(vec![&event]).await?);

        // Create a secret
        let (secret_id, _, _, _, event) =
            mock_vault_note(&mut vault, &encryption_key, "foo", "bar")
                .await?;
        commits.append(&mut event_log.apply(vec![&event]).await?);

        // Update the secret
        let (_, _, _, event) = mock_vault_note_update(
            &mut vault,
            &encryption_key,
            &secret_id,
            "bar",
            "qux",
        )
        .await?;
        if let Some(event) = event {
            commits.append(&mut event_log.apply(vec![&event]).await?);
        }

        // Create another secret
        let (del_id, _, _, _, event) =
            mock_vault_note(&mut vault, &encryption_key, "qux", "baz")
                .await?;
        commits.append(&mut event_log.apply(vec![&event]).await?);

        let event = vault.delete(&del_id).await?;
        if let Some(event) = event {
            commits.append(&mut event_log.apply(vec![&event]).await?);
        }

        Ok((temp, event_log, commits, encryption_key, secret_id))
    }

    #[tokio::test]
    async fn event_log_reduce_build() -> Result<()> {
        let (temp, event_log, _, encryption_key, secret_id) =
            mock_event_log_file().await?;

        assert_eq!(5, event_log.tree().len());

        let vault = FolderReducer::new()
            .reduce(&event_log)
            .await?
            .build(true)
            .await?;

        assert_eq!(1, vault.len());

        let entry = vault.get(&secret_id);
        assert!(entry.is_some());

        if let Some(VaultCommit(_, VaultEntry(meta_aead, secret_aead))) =
            entry
        {
            let meta = vault.decrypt(&encryption_key, meta_aead).await?;
            let secret = vault.decrypt(&encryption_key, secret_aead).await?;
            let meta: SecretMeta = decode(&meta).await?;
            let secret: Secret = decode(&secret).await?;

            assert_eq!("bar", meta.label());
            assert_eq!("qux", {
                match &secret {
                    Secret::Note { text, .. } => text.expose_secret(),
                    _ => panic!("unexpected secret type"),
                }
            });
        }

        temp.close()?;
        Ok(())
    }

    #[tokio::test]
    async fn event_log_reduce_compact() -> Result<()> {
        let (_temp, event_log, _, _encryption_key, _secret_id) =
            mock_event_log_file().await?;

        assert_eq!(5, event_log.tree().len());

        // Get a vault so we can assert on the compaction result
        let vault = FolderReducer::new()
            .reduce(&event_log)
            .await?
            .build(true)
            .await?;

        // Get the compacted series of events
        let events = FolderReducer::new()
            .reduce(&event_log)
            .await?
            .compact()
            .await?;

        assert_eq!(2, events.len());

        let compact_temp = NamedTempFile::new()?;
        let mut compact = FolderEventLog::new(compact_temp.path()).await?;
        for event in events {
            compact.apply(vec![&event]).await?;
        }

        let compact_vault = FolderReducer::new()
            .reduce(&compact)
            .await?
            .build(true)
            .await?;
        assert_eq!(vault, compact_vault);

        Ok(())
    }
}