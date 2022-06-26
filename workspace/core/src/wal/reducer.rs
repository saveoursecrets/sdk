//! Iterate a WAL provider and reduce all the events
//! so that a single vault can be built.
//!
//! The WAL must have a create vault event as the first record
//! and create vault events after the first record are not permitted.
//!
//! Uses a simple last event wins strategy.
//!
use std::{borrow::Cow, collections::HashMap, fmt};

use crate::{
    crypto::AeadPack,
    events::WalEvent,
    secret::SecretId,
    vault::{Vault, VaultCommit},
    wal::{file::WalFile, WalProvider},
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

    /// Reduce the events in the given iterator.
    pub fn reduce<T: fmt::Debug>(
        mut self,
        wal: &'a mut (impl WalProvider<Item = T> + 'a),
    ) -> Result<Self> {
        let mut it = wal.iter()?;
        if let Some(first) = it.next() {
            let first_log = first?;
            let first_event = wal.event_data(first_log)?;

            if let WalEvent::CreateVault(vault) = first_event {
                self.vault = Some(vault.clone());
                for record in it {
                    let log = record?;
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
        Ok(self)
    }

    /// Consume this reducer and build a vault.
    pub fn build(self) -> Result<Vault> {
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
            Ok(vault)
        } else {
            Ok(Default::default())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::*;
    use anyhow::Result;

    #[test]
    fn wal_reduce_events() -> Result<()> {
        let (temp, mut wal, _, _) = mock_wal_file()?;
        let vault = WalReducer::new().reduce(&mut wal)?.build()?;

        println!("Got vault with len {}", vault.len());

        temp.close()?;
        Ok(())
    }
}
