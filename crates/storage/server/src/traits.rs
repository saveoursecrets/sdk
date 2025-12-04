//! Server storage implementations.
use crate::Result;
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_backend::FolderEventLog;
use sos_core::{
    device::{DevicePublicKey, TrustedDevice},
    events::patch::FolderDiff,
    AccountId, Paths, Recipient, VaultFlags, VaultId,
};
use sos_sync::CreateSet;
use sos_vault::{Summary, Vault};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Trait for server storage implementations.
#[async_trait]
pub trait ServerAccountStorage {
    /// Account identifier.
    fn account_id(&self) -> &AccountId;

    /// List the public keys of trusted devices.
    fn list_device_keys(&self) -> HashSet<&DevicePublicKey>;

    /// Computed storage directories for the provider.
    fn paths(&self) -> Arc<Paths>;

    /// Folder event logs.
    fn folders(&self) -> &HashMap<VaultId, Arc<RwLock<FolderEventLog>>>;

    /// Mutable folder event logs.
    fn folders_mut(
        &mut self,
    ) -> &mut HashMap<VaultId, Arc<RwLock<FolderEventLog>>>;

    /// Set the collection of trusted devices.
    fn set_devices(&mut self, devices: IndexSet<TrustedDevice>);

    /// Rename the account.
    async fn rename_account(&self, name: &str) -> Result<()>;

    /// Read a vault from storage.
    async fn read_vault(&self, folder_id: &VaultId) -> Result<Vault>;

    /// Write a vault to storage.
    async fn write_vault(&self, vault: &Vault) -> Result<()>;

    /*
    /// Read the login vault from the storage.
    async fn read_login_vault(&self) -> Result<Vault>;
    */

    /// Write a login vault to storage.
    async fn write_login_vault(&self, vault: &Vault) -> Result<()>;

    /// Replace all the events for a folder.
    async fn replace_folder(
        &self,
        folder_id: &VaultId,
        diff: &FolderDiff,
    ) -> Result<(FolderEventLog, Vault)>;

    /// Update folder flags.
    async fn set_folder_flags(
        &self,
        folder_id: &VaultId,
        flags: VaultFlags,
    ) -> Result<()>;

    /// Import an account from a change set of event logs.
    ///
    /// Does not prepare the identity vault event log
    /// which should be done by calling `initialize_account()`
    /// before creating new storage.
    ///
    /// Intended to be used on a server to create a new
    /// account from a collection of patches.
    async fn import_account(
        &mut self,
        account_data: &CreateSet,
    ) -> Result<()>;

    /// Load folders from the local disc.
    ///
    /// Creates the in-memory event logs for each folder on disc.
    async fn load_folders(&mut self) -> Result<Vec<Summary>>;

    /// Import a folder into an existing account.
    ///
    /// If a folder with the same identifier already exists
    /// it is overwritten.
    ///
    /// Buffer is the encoded representation of the vault.
    async fn import_folder(
        &mut self,
        id: &VaultId,
        buffer: &[u8],
    ) -> Result<()>;

    /// Set the name of a folder.
    async fn rename_folder(&mut self, id: &VaultId, name: &str)
        -> Result<()>;

    /// Delete a folder.
    async fn delete_folder(&mut self, id: &VaultId) -> Result<()>;

    /// Delete this account.
    async fn delete_account(&mut self) -> Result<()>;

    /// Set account recipient information.
    async fn set_recipient(&mut self, recipient: Recipient) -> Result<()>;

    /// Get account recipient information.
    async fn get_recipient(&mut self) -> Result<Option<Recipient>>;

    /// Create a shared folder.
    async fn create_shared_folder(
        &mut self,
        vault: &[u8],
        recipients: &[Recipient],
    ) -> Result<()>;
}
