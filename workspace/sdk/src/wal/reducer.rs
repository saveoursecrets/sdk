//! Iterate a WAL provider and reduce all the events
//! so that a single vault can be built or a compacted
//! WAL log can be created.
//!
//! The WAL must have a create vault event as the first record
//! and create vault events after the first record are not permitted.
//!
//! Uses a simple last event wins strategy.
//!
use std::{borrow::Cow, collections::HashMap};

use crate::{
    crypto::AeadPack,
    decode, encode,
    events::SyncEvent,
    vault::{secret::SecretId, Vault, VaultCommit},
    wal::file::WalFile,
    Error, Result,
};

/// Reducer for WAL events.
#[derive(Default)]
pub struct WalReducer<'a> {
    /// Buffer for the create or last update vault event.
    vault: Option<Cow<'a, [u8]>>,
    /// Last encountered vault name.
    vault_name: Option<Cow<'a, str>>,
    /// Last encountered vault meta data.
    vault_meta: Option<Cow<'a, Option<AeadPack>>>,
    /// Map of the reduced secrets.
    secrets: HashMap<SecretId, Cow<'a, VaultCommit>>,
}

impl<'a> WalReducer<'a> {
    /// Create a new reducer.
    pub fn new() -> Self {
        Default::default()
    }

    /// Split a vault into a truncated vault and a collection
    /// of WAL events that represent the vault.
    ///
    /// The truncated vault represents the header of the vault and
    /// has no contents.
    pub fn split(vault: Vault) -> Result<(Vault, Vec<SyncEvent<'static>>)> {
        let mut events = Vec::with_capacity(vault.len() + 1);
        let header = vault.header().clone();
        let head = Vault::from(header);

        let buffer = encode(&head)?;
        events.push(SyncEvent::CreateVault(Cow::Owned(buffer)));
        for (id, entry) in vault {
            let event = SyncEvent::CreateSecret(id, Cow::Owned(entry));
            events.push(event);
        }

        events.sort();

        Ok((head, events))
    }

    /// Reduce the events in the given iterator.
    pub fn reduce(
        mut self,
        wal: &'a WalFile,
    ) -> Result<Self> {
        let mut it = wal.iter()?;
        if let Some(first) = it.next() {
            let log = first?;
            let event = wal.event_data(&log)?;

            if let SyncEvent::CreateVault(vault) = event {
                self.vault = Some(vault.clone());
                for record in it {
                    let log = record?;
                    let event = wal.event_data(&log)?;
                    match event {
                        SyncEvent::Noop => unreachable!(),
                        SyncEvent::CreateVault(_) => {
                            return Err(Error::WalCreateEventOnlyFirst)
                        }
                        SyncEvent::SetVaultName(name) => {
                            self.vault_name = Some(name.clone());
                        }
                        SyncEvent::SetVaultMeta(meta) => {
                            self.vault_meta = Some(meta.clone());
                        }
                        SyncEvent::CreateSecret(id, entry) => {
                            self.secrets.insert(id, entry.clone());
                        }
                        SyncEvent::UpdateSecret(id, entry) => {
                            self.secrets.insert(id, entry.clone());
                        }
                        SyncEvent::DeleteSecret(id) => {
                            self.secrets.remove(&id);
                        }
                        _ => {}
                    }
                }
            } else {
                return Err(Error::WalCreateEventMustBeFirst);
            }
        }

        Ok(self)
    }

    /// Create a series of new WAL events that represent
    /// a compacted version of the WAL.
    ///
    /// This series of events can then be appended to a
    /// new WAL log to create a compact version with
    /// history pruned.
    ///
    /// Note that using this to compact a WAL log is lossy;
    /// log record timestamps will be reset.
    ///
    /// The commit tree returned here will be invalid once
    /// the new series of events have been applied so callers
    /// must generate a new commit tree once the new WAL log has
    /// been created.
    pub fn compact(self) -> Result<Vec<SyncEvent<'a>>> {
        if let Some(vault) = self.vault {
            let mut events = Vec::new();

            let mut vault: Vault = decode(&vault)?;
            if let Some(name) = self.vault_name {
                vault.set_name(name.into_owned());
            }

            if let Some(meta) = self.vault_meta {
                vault.header_mut().set_meta(meta.into_owned());
            }

            let buffer = encode(&vault)?;
            events.push(SyncEvent::CreateVault(Cow::Owned(buffer)));
            for (id, entry) in self.secrets {
                let entry = entry.into_owned();
                events.push(SyncEvent::CreateSecret(id, Cow::Owned(entry)));
            }
            Ok(events)
        } else {
            Ok(Vec::new())
        }
    }

    /// Consume this reducer and build a vault.
    pub fn build(self) -> Result<Vault> {
        if let Some(vault) = self.vault {
            let mut vault: Vault = decode(&vault)?;
            if let Some(name) = self.vault_name {
                vault.set_name(name.into_owned());
            }

            if let Some(meta) = self.vault_meta {
                vault.header_mut().set_meta(meta.into_owned());
            }

            for (id, entry) in self.secrets {
                let entry = entry.into_owned();
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
        crypto::secret_key::SecretKey,
        decode,
        test_utils::*,
        vault::{
            secret::{Secret, SecretId, SecretMeta},
            VaultAccess, VaultCommit, VaultEntry,
        },
        wal::file::WalFile,
    };
    use anyhow::Result;
    use secrecy::ExposeSecret;
    use tempfile::NamedTempFile;

    fn mock_wal_file(
    ) -> Result<(NamedTempFile, WalFile, Vec<CommitHash>, SecretKey, SecretId)>
    {
        let (encryption_key, _, _) = mock_encryption_key()?;
        let (_, mut vault, buffer) = mock_vault_file()?;

        let temp = NamedTempFile::new()?;
        let mut wal = WalFile::new(temp.path())?;

        let mut commits = Vec::new();

        // Create the vault
        let event = SyncEvent::CreateVault(Cow::Owned(buffer));
        commits.push(wal.append_event(event)?);

        // Create a secret
        let (secret_id, _, _, _, event) =
            mock_vault_note(&mut vault, &encryption_key, "foo", "bar")?;
        commits.push(wal.append_event(event)?);

        // Update the secret
        let (_, _, _, event) = mock_vault_note_update(
            &mut vault,
            &encryption_key,
            &secret_id,
            "bar",
            "qux",
        )?;
        if let Some(event) = event {
            commits.push(wal.append_event(event)?);
        }

        // Create another secret
        let (del_id, _, _, _, event) =
            mock_vault_note(&mut vault, &encryption_key, "qux", "baz")?;
        commits.push(wal.append_event(event)?);

        let event = vault.delete(&del_id)?;
        if let Some(event) = event {
            commits.push(wal.append_event(event)?);
        }

        Ok((temp, wal, commits, encryption_key, secret_id))
    }

    #[test]
    fn wal_reduce_build() -> Result<()> {
        let (temp, wal, _, encryption_key, secret_id) = mock_wal_file()?;

        assert_eq!(5, wal.tree().len());

        let vault = WalReducer::new().reduce(&wal)?.build()?;

        assert_eq!(1, vault.len());

        let entry = vault.get(&secret_id);
        assert!(entry.is_some());

        if let Some(VaultCommit(_, VaultEntry(meta_aead, secret_aead))) =
            entry
        {
            let meta = vault.decrypt(&encryption_key, meta_aead)?;
            let secret = vault.decrypt(&encryption_key, secret_aead)?;
            let meta: SecretMeta = decode(&meta)?;
            let secret: Secret = decode(&secret)?;

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

    #[test]
    fn wal_reduce_compact() -> Result<()> {
        let (_temp, wal, _, _encryption_key, _secret_id) = mock_wal_file()?;

        assert_eq!(5, wal.tree().len());

        // Get a vault so we can assert on the compaction result
        let vault = WalReducer::new().reduce(&wal)?.build()?;

        // Get the compacted series of events
        let events = WalReducer::new().reduce(&wal)?.compact()?;

        assert_eq!(2, events.len());

        let compact_temp = NamedTempFile::new()?;
        let mut compact = WalFile::new(compact_temp.path())?;
        for event in events {
            compact.append_event(event)?;
        }

        let compact_vault = WalReducer::new().reduce(&compact)?.build()?;
        assert_eq!(vault, compact_vault);

        Ok(())
    }
}
