//! Storage provider trait.

use std::path::PathBuf;
use async_trait::async_trait;
use secrecy::SecretString;

use sos_core::{
    constants::{PATCH_EXT, WAL_EXT, VAULT_EXT},
    vault::{Header, Summary, Vault},
    events::WalEvent,
    wal::WalProvider,
    Gatekeeper,
    PatchProvider,
};

use crate::{
    client::{node_state::NodeState, Result},
};

/// Trait for storage providers.
#[async_trait]
pub trait StorageProvider<W, P>
where
    W: WalProvider + Send + Sync + 'static,
    P: PatchProvider + Send + Sync + 'static,
{
    /// Get the state for this storage provider.
    fn state(&self) -> &NodeState;

    /// Get a mutable reference to the state for this storage provider.
    fn state_mut(&mut self) -> &mut NodeState;

    /// Compute the storage directory for the user.
    fn storage_dir(&self) -> PathBuf;

    /// Get the path to a WAL file.
    fn wal_path(&self, summary: &Summary) -> PathBuf {
        let file_name = format!("{}.{}", summary.id(), WAL_EXT);
        self.storage_dir().join(&file_name)
    }

    /// Get the path to a vault file.
    fn vault_path(&self, summary: &Summary) -> PathBuf {
        let file_name = format!("{}.{}", summary.id(), VAULT_EXT);
        self.storage_dir().join(&file_name)
    }

    /// Get the path to a patch file.
    fn patch_path(&self, summary: &Summary) -> PathBuf {
        let file_name = format!("{}.{}", summary.id(), PATCH_EXT);
        self.storage_dir().join(&file_name)
    }

    /// Get the vault summaries for this storage.
    fn vaults(&self) -> &[Summary] {
        self.state().summaries()
    }

    /// Get the current in-memory vault access.
    fn current(&self) -> Option<&Gatekeeper> {
        self.state().current()
    }

    /// Get a mutable reference to the current in-memory vault access.
    fn current_mut(&mut self) -> Option<&mut Gatekeeper> {
        self.state_mut().current_mut()
    }

    /// Get the history of events for a vault.
    fn history(
        &self,
        summary: &Summary,
    ) -> Result<Vec<(W::Item, WalEvent<'_>)>>;

    /// Change the password for a vault.
    ///
    /// If the target vault is the currently selected vault
    /// the currently selected vault is unlocked with the new
    /// passphrase on success.
    async fn change_password(
        &mut self,
        vault: &Vault,
        current_passphrase: SecretString,
        new_passphrase: SecretString,
    ) -> Result<SecretString>;

    /// Compact a WAL file.
    async fn compact(&mut self, summary: &Summary) -> Result<(u64, u64)>;

    /// Create a new account and default login vault.
    async fn create_account(
        &mut self,
        name: Option<String>,
        passphrase: Option<String>,
    ) -> Result<(SecretString, Summary)>;

    /// Create a new vault.
    async fn create_vault(
        &mut self,
        name: String,
        passphrase: Option<String>,
    ) -> Result<(SecretString, Summary)>;

    /// Remove a vault.
    async fn remove_vault(&mut self, summary: &Summary) -> Result<()>;

    /// Load vault summaries.
    async fn load_vaults(&mut self) -> Result<&[Summary]>;

    /// Attempt to set the vault name for a vault.
    async fn set_vault_name(
        &mut self,
        summary: &Summary,
        name: &str,
    ) -> Result<()>;

    /// Load a vault, unlock it and set it as the current vault.
    fn open_vault(
        &mut self,
        summary: &Summary,
        passphrase: &str,
    ) -> Result<()>;

    /// Close the currently selected vault.
    fn close_vault(&mut self);

    /// Verify a WAL log.
    fn verify(&self, summary: &Summary) -> Result<()>;
}
