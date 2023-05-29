//! Local node state exposing an in-memory cache
//! of vault summaries and a currently selected vault.
use super::{Error, Result};

use sos_sdk::{
    search::SearchIndex,
    secrecy::SecretString,
    vault::{Gatekeeper, Summary, Vault, VaultRef, VaultWriter},
};

use std::{path::PathBuf, sync::Arc};

use tokio::sync::RwLock;

/// Manages the state of a node.
pub struct ProviderState {
    /// Whether this state should mirror changes to disc.
    mirror: bool,
    /// Vaults managed by this state.
    summaries: Vec<Summary>,
    /// Currently selected in-memory vault.
    current: Option<Gatekeeper>,
}

impl ProviderState {
    /// Create a new node state.
    pub fn new(mirror: bool) -> Self {
        Self {
            mirror,
            summaries: Default::default(),
            current: None,
        }
    }

    /// Determine if mirroring is enabled.
    pub fn mirror(&self) -> bool {
        self.mirror
    }

    /// Get the current in-memory vault access.
    pub fn current(&self) -> Option<&Gatekeeper> {
        self.current.as_ref()
    }

    /// Get a mutable reference to the current in-memory vault access.
    pub fn current_mut(&mut self) -> Option<&mut Gatekeeper> {
        self.current.as_mut()
    }

    /// Get the vault summaries this state is managing.
    pub fn summaries(&self) -> &[Summary] {
        self.summaries.as_slice()
    }

    /// Get the vault summaries this state is managing.
    pub fn summaries_mut(&mut self) -> &mut [Summary] {
        self.summaries.as_mut_slice()
    }

    /// Set the summaries for this state.
    pub fn set_summaries(&mut self, summaries: Vec<Summary>) {
        self.summaries = summaries;
        self.summaries.sort();
    }

    /// Add a summary to this state.
    pub fn add_summary(&mut self, summary: Summary) {
        self.summaries.push(summary);
        self.summaries.sort();
    }

    /// Remove a summary from this state.
    pub fn remove_summary(&mut self, summary: &Summary) {
        let index =
            self.summaries.iter().position(|s| s.id() == summary.id());
        if let Some(index) = index {
            self.summaries.remove(index);
            self.summaries.sort();
        }
    }

    /// Find a summary in this state by reference.
    pub fn find_vault(&self, vault: &VaultRef) -> Option<&Summary> {
        match vault {
            VaultRef::Name(name) => {
                self.summaries.iter().find(|s| s.name() == name)
            }
            VaultRef::Id(id) => self.summaries.iter().find(|s| s.id() == id),
        }
    }

    /// Find a summary in this state.
    pub fn find<F>(&self, predicate: F) -> Option<&Summary>
    where
        F: FnMut(&&Summary) -> bool,
    {
        self.summaries.iter().find(predicate)
    }

    /// Set the current vault and unlock it.
    pub async fn open_vault(
        &mut self,
        passphrase: SecretString,
        vault: Vault,
        vault_path: PathBuf,
        index: Option<Arc<RwLock<SearchIndex>>>,
    ) -> Result<()> {
        let mut keeper = if self.mirror {
            let vault_file = VaultWriter::open(&vault_path).await?;
            let mirror = VaultWriter::new(vault_path, vault_file)?;
            Gatekeeper::new_mirror(vault, mirror, index)
        } else {
            Gatekeeper::new(vault, index)
        };

        keeper
            .unlock(passphrase)
            .map_err(|_| Error::VaultUnlockFail)?;
        self.current = Some(keeper);
        Ok(())
    }

    /// Add this vault to the search index.
    pub(crate) async fn create_search_index(&mut self) -> Result<()> {
        let keeper = self.current_mut().ok_or_else(|| Error::NoOpenVault)?;
        keeper.create_search_index().await?;
        Ok(())
    }

    /// Close the currently open vault.
    ///
    /// When a vault is open it is locked before being closed.
    ///
    /// If no vault is open this is a noop.
    pub fn close_vault(&mut self) {
        if let Some(current) = self.current_mut() {
            current.lock();
        }
        self.current = None;
    }
}
