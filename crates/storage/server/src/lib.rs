mod error;

pub mod filesystem;
pub mod server_helpers;
mod traits;

pub use error::Error;
pub use traits::ServerAccountStorage;

/// Result type for the server module.
pub type Result<T> = std::result::Result<T, Error>;

use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::Arc;
use crate::traits::{ServerAccountStorage, SyncStorage};
use crate::filesystem::Paths;
use crates::sdk::identity::Address;
use crates::sdk::crypto::DevicePublicKey;
use crates::sdk::vault::{Secret, SecretId, Vault, VaultId};

/// Server storage backed by filesystem or database.
pub enum ServerStorage {
    /// Filesystem storage.
    FileSystem(filesystem::ServerFileStorage),
    /// Database storage (TODO: switch impl).
    Database(filesystem::ServerFileStorage),
}

#[async_trait]
impl SyncStorage for ServerStorage {
    async fn sync(&self) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => fs.sync().await,
            ServerStorage::Database(db) => db.sync().await,
        }
    }
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
}
