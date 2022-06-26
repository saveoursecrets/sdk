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
    commit_tree::CommitTree,
    crypto::AeadPack,
    events::WalEvent,
    secret::SecretId,
    vault::{Vault, VaultCommit},
    wal::{WalItem, WalProvider},
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
    /// Commit tree.
    tree: CommitTree,
}

impl<'a> WalReducer<'a> {
    /// Create a new reducer.
    pub fn new() -> Self {
        Default::default()
    }

    /// Reduce the events in the given iterator.
    pub fn reduce<T: WalItem>(
        mut self,
        wal: &'a mut (impl WalProvider<Item = T> + 'a),
    ) -> Result<Self> {
        let mut it = wal.iter()?;
        if let Some(first) = it.next() {
            let log = first?;
            self.tree.insert(log.commit());
            let event = wal.event_data(log)?;

            if let WalEvent::CreateVault(vault) = event {
                self.vault = Some(vault.clone());
                for record in it {
                    let log = record?;
                    self.tree.insert(log.commit());
                    let event = wal.event_data(log)?;
                    match event {
                        WalEvent::Noop => unreachable!(),
                        WalEvent::CreateVault(_) => {
                            return Err(Error::WalCreateEventOnlyFirst)
                        }
                        WalEvent::UpdateVault(vault) => {
                            self.vault = Some(vault.clone());
                        }
                        WalEvent::SetVaultName(name) => {
                            self.vault_name = Some(name.clone());
                        }
                        WalEvent::SetVaultMeta(meta) => {
                            self.vault_meta = Some(meta.clone());
                        }
                        WalEvent::CreateSecret(id, entry) => {
                            self.secrets.insert(id, entry.clone());
                        }
                        WalEvent::UpdateSecret(id, entry) => {
                            self.secrets.insert(id, entry.clone());
                        }
                        WalEvent::DeleteSecret(id) => {
                            self.secrets.remove(&id);
                        }
                    }
                }
            } else {
                return Err(Error::WalCreateEventMustBeFirst);
            }
        }

        self.tree.commit();
        Ok(self)
    }

    /// Consume this reducer and build a vault.
    pub fn build(self) -> Result<(Vault, CommitTree)> {
        if let Some(vault) = self.vault {
            let mut vault = Vault::read_buffer(&vault)?;

            if let Some(name) = self.vault_name {
                vault.set_name(name.into_owned());
            }

            if let Some(meta) = self.vault_meta {
                vault.header_mut().set_meta(meta.into_owned());
            }

            for (id, entry) in self.secrets {
                let entry = entry.into_owned();
                vault.insert(id, entry);
            }
            Ok((vault, self.tree))
        } else {
            Ok((Default::default(), self.tree))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        crypto::secret_key::SecretKey,
        secret::{Secret, SecretId, SecretMeta},
        test_utils::*,
        vault::{decode, CommitHash, VaultAccess, VaultCommit, VaultEntry},
        wal::file::WalFile,
    };
    use anyhow::Result;
    use tempfile::NamedTempFile;

    fn mock_wal_file(
    ) -> Result<(NamedTempFile, WalFile, Vec<CommitHash>, SecretKey, SecretId)>
    {
        let (encryption_key, _) = mock_encryption_key()?;
        let (_, mut vault, buffer) = mock_vault_file()?;

        let temp = NamedTempFile::new()?;
        let mut wal = WalFile::new(temp.path().to_path_buf())?;

        let mut commits = Vec::new();

        // Create the vault
        let event = WalEvent::CreateVault(Cow::Owned(buffer));
        commits.push(wal.append_event(event)?);

        // Create a secret
        let (secret_id, _, _, _, event) =
            mock_vault_note(&mut vault, &encryption_key, "foo", "bar")?;
        commits.push(wal.append_event((&event).into())?);

        // Update the secret
        let (_, _, _, event) = mock_vault_note_update(
            &mut vault,
            &encryption_key,
            &secret_id,
            "bar",
            "qux",
        )?;
        if let Some(event) = event {
            commits.push(wal.append_event((&event).into())?);
        }

        // Create another secret
        let (del_id, _, _, _, event) =
            mock_vault_note(&mut vault, &encryption_key, "qux", "baz")?;
        commits.push(wal.append_event((&event).into())?);

        let event = vault.delete(&del_id)?;
        if let Some(event) = event {
            commits.push(wal.append_event((&event).into())?);
        }

        Ok((temp, wal, commits, encryption_key, secret_id))
    }

    #[test]
    fn wal_reduce_events() -> Result<()> {
        let (temp, mut wal, _, encryption_key, secret_id) = mock_wal_file()?;
        let (vault, tree) = WalReducer::new().reduce(&mut wal)?.build()?;

        assert_eq!(1, vault.len());
        assert_eq!(5, tree.len());

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
                    Secret::Note(text) => text,
                    _ => panic!("unexpected secret type"),
                }
            });
        }

        temp.close()?;
        Ok(())
    }
}
