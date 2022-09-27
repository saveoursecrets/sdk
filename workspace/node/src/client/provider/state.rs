//! Local node state exposing an in-memory cache
//! of vault summaries and a currently selected vault.
use super::{Error, Result};

use sos_core::{
    secret::SecretRef,
    vault::{Summary, Vault},
    Gatekeeper, VaultFileAccess,
};

use std::path::PathBuf;

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

    /// Attempt to find a summary in this state.
    pub fn find_vault(&self, vault: &SecretRef) -> Option<&Summary> {
        match vault {
            SecretRef::Name(name) => {
                self.summaries.iter().find(|s| s.name() == name)
            }
            SecretRef::Id(id) => self.summaries.iter().find(|s| s.id() == id),
        }
    }

    /// Set the current vault and unlock it.
    pub fn open_vault(
        &mut self,
        passphrase: &str,
        vault: Vault,
        vault_path: PathBuf,
    ) -> Result<()> {
        let mut keeper = if self.mirror {
            let mirror = Box::new(VaultFileAccess::new(vault_path)?);
            Gatekeeper::new_mirror(vault, mirror)
        } else {
            Gatekeeper::new(vault)
        };
        keeper
            .unlock(passphrase)
            .map_err(|_| Error::VaultUnlockFail)?;
        keeper.create_index()?;
        self.current = Some(keeper);
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
