//! Client storage implementations.
use crate::Result;
use async_trait::async_trait;
use indexmap::IndexSet;
use sos_core::{
    device::{DevicePublicKey, TrustedDevice},
    AccountId, Paths, VaultId,
};
use sos_login::FolderKeys;
use sos_sdk::vault::Summary;
use sos_sync::{CreateSet, MergeOutcome, SyncStorage, UpdateSet};
use sos_vault::FolderRef;
use std::collections::HashSet;
use std::sync::Arc;

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

    /// Find a summary in this storage.
    fn find_folder(&self, vault: &FolderRef) -> Option<&Summary>;

    /// Find a summary in this storage.
    fn find<F>(&self, predicate: F) -> Option<&Summary>
    where
        F: FnMut(&&Summary) -> bool;

    /// Computed storage paths.
    fn paths(&self) -> Arc<Paths>;

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
