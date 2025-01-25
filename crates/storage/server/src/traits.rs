//! Server storage implementations.
use crate::Result;
use async_trait::async_trait;
use sos_core::{device::DevicePublicKey, AccountId, Paths, VaultId};
use sos_sdk::vault::Summary;
use sos_sync::{CreateSet, MergeOutcome, SyncStorage, UpdateSet};
use std::collections::HashSet;
use std::sync::Arc;

/// Trait for server storage implementations.
#[async_trait]
pub trait ServerAccountStorage: SyncStorage {
    /// Account identifier.
    fn account_id(&self) -> &AccountId;

    /// List the public keys of trusted devices.
    fn list_device_keys(&self) -> HashSet<&DevicePublicKey>;

    /// Computed storage directories for the provider.
    fn paths(&self) -> Arc<Paths>;

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

    /// Update an account from a change set of event logs and
    /// event diffs.
    ///
    /// Overwrites all existing account data with the event logs
    /// in the change set.
    ///
    /// Intended to be used to perform a destructive overwrite
    /// when changing the encryption cipher or other events
    /// which rewrite the account data.
    async fn update_account(
        &mut self,
        mut update_set: UpdateSet,
        outcome: &mut MergeOutcome,
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
}
