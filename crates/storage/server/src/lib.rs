mod error;

pub mod filesystem;
pub mod server_helpers;
mod traits;

pub use error::Error;
pub use traits::ServerAccountStorage;

/// Result type for the server module.
pub type Result<T> = std::result::Result<T, Error>;

use crate::filesystem::Paths;
use crate::traits::{ServerAccountStorage, SyncStorage};
use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::Arc;
use sos_sdk::{
    device::DevicePublicKey,
    events::FolderPatch,
    signer::ecdsa::Address,
    vault::{Summary, VaultId},
};
use sos_sync::{CreateSet, MergeOutcome, UpdateSet};

/// Server storage backed by filesystem or database.
pub enum ServerStorage {
    /// Filesystem storage.
    FileSystem(filesystem::ServerFileStorage),
    /// Database storage (TODO: switch impl).
    Database(filesystem::ServerFileStorage),
}

#[async_trait]
impl ServerAccountStorage for ServerStorage {
    fn address(&self) -> &Address {
        match self {
            ServerStorage::FileSystem(fs) => fs.address(),
            ServerStorage::Database(db) => db.address(),
        }
    }

    fn list_device_keys(&self) -> HashSet<&DevicePublicKey> {
        match self {
            ServerStorage::FileSystem(fs) => fs.list_device_keys(),
            ServerStorage::Database(db) => db.list_device_keys(),
        }
    }

    fn paths(&self) -> Arc<Paths> {
        match self {
            ServerStorage::FileSystem(fs) => fs.paths(),
            ServerStorage::Database(db) => db.paths(),
        }
    }

    async fn import_account(&mut self, account_data: &CreateSet) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => fs.import_account(account_data).await,
            ServerStorage::Database(db) => db.import_account(account_data).await,
        }
    }

    async fn update_account(&mut self, update_set: UpdateSet, outcome: &mut MergeOutcome) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => fs.update_account(update_set, outcome).await,
            ServerStorage::Database(db) => db.update_account(update_set, outcome).await,
        }
    }

    async fn load_folders(&mut self) -> Result<Vec<Summary>> {
        match self {
            ServerStorage::FileSystem(fs) => fs.load_folders().await,
            ServerStorage::Database(db) => db.load_folders().await,
        }
    }

    async fn import_folder(&mut self, id: &VaultId, buffer: &[u8]) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => fs.import_folder(id, buffer).await,
            ServerStorage::Database(db) => db.import_folder(id, buffer).await,
        }
    }

    async fn delete_folder(&mut self, id: &VaultId) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => fs.delete_folder(id).await,
            ServerStorage::Database(db) => db.delete_folder(id).await,
        }
    }

    async fn rename_folder(&mut self, id: &VaultId, name: &str) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => fs.rename_folder(id, name).await,
            ServerStorage::Database(db) => db.rename_folder(id, name).await,
        }
    }

    async fn delete_account(&mut self) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => fs.delete_account().await,
            ServerStorage::Database(db) => db.delete_account().await,
        }
    }
}
