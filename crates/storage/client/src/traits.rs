//! Client storage implementations.
use crate::{AccountPack, Result};
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_core::{
    crypto::AccessKey,
    device::TrustedDevice,
    events::{Event, ReadEvent},
    AccountId, Paths, VaultId,
};
use sos_login::FolderKeys;
use sos_sdk::{
    events::{patch::FolderPatch, EventRecord},
    vault::Summary,
};
use sos_vault::FolderRef;
use std::{collections::HashMap, sync::Arc};

#[cfg(feature = "archive")]
use sos_filesystem::archive::RestoreTargets;

#[cfg(feature = "search")]
use sos_search::{AccountSearch, DocumentCount};

// pub trait ClientAccountStorage: SyncStorage {}

/// Trait for client storage implementations.
#[async_trait]
pub trait ClientAccountStorage {
    /// Account identifier.
    fn account_id(&self) -> &AccountId;

    /// Collection of trusted devices.
    fn devices(&self) -> &IndexSet<TrustedDevice>;

    /// List the in-memory folders.
    fn list_folders(&self) -> &[Summary];

    /// Currently open folder.
    fn current_folder(&self) -> Option<Summary>;

    /// Find a folder in this storage by reference.
    fn find_folder(&self, vault: &FolderRef) -> Option<&Summary>;

    /// Find a folder in this storage using a predicate.
    fn find<F>(&self, predicate: F) -> Option<&Summary>
    where
        F: FnMut(&&Summary) -> bool;

    /// Computed storage paths.
    fn paths(&self) -> Arc<Paths>;

    /// Mark a folder as the currently open folder.
    async fn open_folder(&mut self, summary: &Summary) -> Result<ReadEvent>;

    /// Close the current open folder.
    fn close_folder(&mut self);

    /// Create the data for a new account.
    async fn create_account(
        &mut self,
        account: &AccountPack,
    ) -> Result<Vec<Event>>;

    /// Create folders from a collection of folder patches.
    ///
    /// If the folders already exist they will be overwritten.
    async fn import_folder_patches(
        &mut self,
        patches: HashMap<VaultId, FolderPatch>,
    ) -> Result<()>;

    /// Restore a folder from an event log.
    async fn restore_folder(
        &mut self,
        folder_id: &VaultId,
        records: Vec<EventRecord>,
        key: &AccessKey,
    ) -> Result<Summary>;

    /// Read folders from the local disc and create the in-memory
    /// event logs for each folder on disc.
    async fn load_folders(&mut self) -> Result<&[Summary]>;

    /// Delete a folder.
    async fn delete_folder(
        &mut self,
        summary: &Summary,
        apply_event: bool,
    ) -> Result<Vec<Event>>;

    /// Remove a folder from the cache.
    async fn remove_folder(&mut self, folder_id: &VaultId) -> Result<bool>;

    /// Restore vaults from an archive.
    #[cfg(feature = "archive")]
    async fn restore_archive(
        &mut self,
        targets: &RestoreTargets,
        folder_keys: &FolderKeys,
    ) -> Result<()>;

    /// Set the password for file encryption.
    #[cfg(feature = "files")]
    fn set_file_password(
        &mut self,
        file_password: Option<secrecy::SecretString>,
    );

    /// Search index reference.
    #[cfg(feature = "search")]
    fn index(&self) -> Result<&AccountSearch>;

    /// Mutable search index reference.
    #[cfg(feature = "search")]
    fn index_mut(&mut self) -> Result<&mut AccountSearch>;

    /// Initialize the search index.
    ///
    /// This should be called after a user has signed in to
    /// create the initial search index.
    #[cfg(feature = "search")]
    async fn initialize_search_index(
        &mut self,
        keys: &FolderKeys,
    ) -> Result<(DocumentCount, Vec<Summary>)>;

    /// Build the search index for all folders.
    #[cfg(feature = "search")]
    async fn build_search_index(
        &mut self,
        keys: &FolderKeys,
    ) -> Result<DocumentCount>;
}
