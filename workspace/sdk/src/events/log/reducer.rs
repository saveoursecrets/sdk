use std::collections::{HashMap, HashSet};

use crate::{
    commit::CommitHash,
    crypto::AeadPack,
    decode, encode,
    events::{AccountEvent, AccountEventLog, FolderEventLog, WriteEvent},
    vault::{secret::SecretId, Vault, VaultCommit, VaultId},
    Error, Result,
};

use indexmap::IndexMap;

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
                AccountEvent::CreateFolder(id)
                | AccountEvent::UpdateFolder(id)
                | AccountEvent::ChangeFolderPassword(id) => {
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

/// Reduce log events to a vault.
#[derive(Default)]
pub struct EventReducer {
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

impl EventReducer {
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

    /// Reduce the events in the given iterator.
    pub async fn reduce(
        mut self,
        event_log: &FolderEventLog,
    ) -> Result<EventReducer> {
        let mut it = event_log.iter().await?;
        if let Some(log) = it.next_entry().await? {
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

                while let Some(log) = it.next_entry().await? {
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
                            self.secrets.remove(&id);
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
    pub async fn build(self) -> Result<Vault> {
        if let Some(vault) = self.vault {
            let mut vault: Vault = decode(&vault).await?;
            if let Some(name) = self.vault_name {
                vault.set_name(name);
            }

            if let Some(meta) = self.vault_meta {
                vault.header_mut().set_meta(Some(meta));
            }

            for (id, entry) in self.secrets {
                vault.insert_entry(id, entry);
            }
            Ok(vault)
        } else {
            Ok(Default::default())
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
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
        let mut event_log = FolderEventLog::new_folder(temp.path()).await?;

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

        let vault = EventReducer::new()
            .reduce(&event_log)
            .await?
            .build()
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
        let vault = EventReducer::new()
            .reduce(&event_log)
            .await?
            .build()
            .await?;

        // Get the compacted series of events
        let events = EventReducer::new()
            .reduce(&event_log)
            .await?
            .compact()
            .await?;

        assert_eq!(2, events.len());

        let compact_temp = NamedTempFile::new()?;
        let mut compact =
            FolderEventLog::new_folder(compact_temp.path()).await?;
        for event in events {
            compact.apply(vec![&event]).await?;
        }

        let compact_vault =
            EventReducer::new().reduce(&compact).await?.build().await?;
        assert_eq!(vault, compact_vault);

        Ok(())
    }
}
