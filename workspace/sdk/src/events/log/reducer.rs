use std::{borrow::Cow, collections::HashMap};

use crate::{
    crypto::AeadPack,
    decode, encode,
    events::{Event, EventLogFile, WriteEvent},
    vault::{secret::SecretId, Vault, VaultCommit},
    Error, Result,
};

/// Reduce log events to a vault.
#[derive(Default)]
pub struct EventReducer<'a> {
    /// Buffer for the create or last update vault event.
    vault: Option<Cow<'a, [u8]>>,
    /// Last encountered vault name.
    vault_name: Option<Cow<'a, str>>,
    /// Last encountered vault meta data.
    vault_meta: Option<Cow<'a, Option<AeadPack>>>,
    /// Map of the reduced secrets.
    secrets: HashMap<SecretId, Cow<'a, VaultCommit>>,
}

impl<'a> EventReducer<'a> {
    /// Create a new reducer.
    pub fn new() -> Self {
        Default::default()
    }

    /// Split a vault into a truncated vault and a collection
    /// of events that represent the vault.
    ///
    /// The truncated vault represents the header of the vault and
    /// has no contents.
    pub fn split(vault: Vault) -> Result<(Vault, Vec<WriteEvent<'static>>)> {
        let mut events = Vec::with_capacity(vault.len() + 1);
        let header = vault.header().clone();
        let head: Vault = header.into();

        let buffer = encode(&head)?;
        events.push(WriteEvent::CreateVault(Cow::Owned(buffer)));
        for (id, entry) in vault {
            let event = WriteEvent::CreateSecret(id, Cow::Owned(entry));
            events.push(event);
        }

        events.sort();

        Ok((head, events))
    }

    /// Reduce the events in the given iterator.
    pub fn reduce(mut self, event_log: &'a EventLogFile) -> Result<Self> {
        let mut it = event_log.iter()?;
        if let Some(first) = it.next() {
            let log = first?;
            let event = event_log.event_data(&log)?;

            if let WriteEvent::CreateVault(vault) = event {
                self.vault = Some(vault.clone());
                for record in it {
                    let log = record?;
                    let event = event_log.event_data(&log)?;
                    match event {
                        WriteEvent::CreateVault(_) => {
                            return Err(Error::CreateEventOnlyFirst)
                        }
                        WriteEvent::SetVaultName(name) => {
                            self.vault_name = Some(name.clone());
                        }
                        WriteEvent::SetVaultMeta(meta) => {
                            self.vault_meta = Some(meta.clone());
                        }
                        WriteEvent::CreateSecret(id, entry) => {
                            self.secrets.insert(id, entry.clone());
                        }
                        WriteEvent::UpdateSecret(id, entry) => {
                            self.secrets.insert(id, entry.clone());
                        }
                        WriteEvent::DeleteSecret(id) => {
                            self.secrets.remove(&id);
                        }
                        _ => {}
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
    pub fn compact(self) -> Result<Vec<WriteEvent<'a>>> {
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
            events.push(WriteEvent::CreateVault(Cow::Owned(buffer)));
            for (id, entry) in self.secrets {
                let entry = entry.into_owned();
                events.push(WriteEvent::CreateSecret(id, Cow::Owned(entry)));
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
        events::{Event, EventLogFile, WriteEvent},
        test_utils::*,
        vault::{
            secret::{Secret, SecretId, SecretMeta},
            VaultAccess, VaultCommit, VaultEntry,
        },
    };
    use anyhow::Result;
    use secrecy::ExposeSecret;
    use tempfile::NamedTempFile;

    fn mock_event_log_file() -> Result<(
        NamedTempFile,
        EventLogFile,
        Vec<CommitHash>,
        SecretKey,
        SecretId,
    )> {
        let (encryption_key, _, _) = mock_encryption_key()?;
        let (_, mut vault, buffer) = mock_vault_file()?;

        let temp = NamedTempFile::new()?;
        let mut event_log = EventLogFile::new(temp.path())?;

        let mut commits = Vec::new();

        // Create the vault
        let event = Event::Write(
            *vault.id(),
            WriteEvent::CreateVault(Cow::Owned(buffer)),
        );
        if let Event::Write(_, event) = event {
            commits.push(event_log.append_event(event)?);
        }

        // Create a secret
        let (secret_id, _, _, _, event) =
            mock_vault_note(&mut vault, &encryption_key, "foo", "bar")?;
        if let Event::Write(_, event) = event {
            commits.push(event_log.append_event(event)?);
        }

        // Update the secret
        let (_, _, _, event) = mock_vault_note_update(
            &mut vault,
            &encryption_key,
            &secret_id,
            "bar",
            "qux",
        )?;
        if let Some(Event::Write(_, event)) = event {
            commits.push(event_log.append_event(event)?);
        }

        // Create another secret
        let (del_id, _, _, _, event) =
            mock_vault_note(&mut vault, &encryption_key, "qux", "baz")?;
        if let Event::Write(_, event) = event {
            commits.push(event_log.append_event(event)?);
        }

        let event = vault.delete(&del_id)?;
        if let Some(Event::Write(_, event)) = event {
            commits.push(event_log.append_event(event)?);
        }

        Ok((temp, event_log, commits, encryption_key, secret_id))
    }

    #[test]
    fn event_log_reduce_build() -> Result<()> {
        let (temp, event_log, _, encryption_key, secret_id) =
            mock_event_log_file()?;

        assert_eq!(5, event_log.tree().len());

        let vault = EventReducer::new().reduce(&event_log)?.build()?;

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
    fn event_log_reduce_compact() -> Result<()> {
        let (_temp, event_log, _, _encryption_key, _secret_id) =
            mock_event_log_file()?;

        assert_eq!(5, event_log.tree().len());

        // Get a vault so we can assert on the compaction result
        let vault = EventReducer::new().reduce(&event_log)?.build()?;

        // Get the compacted series of events
        let events = EventReducer::new().reduce(&event_log)?.compact()?;

        assert_eq!(2, events.len());

        let compact_temp = NamedTempFile::new()?;
        let mut compact = EventLogFile::new(compact_temp.path())?;
        for event in events {
            compact.append_event(event)?;
        }

        let compact_vault = EventReducer::new().reduce(&compact)?.build()?;
        assert_eq!(vault, compact_vault);

        Ok(())
    }
}
