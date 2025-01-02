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

    async fn add_device_key(&self, key: DevicePublicKey) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => fs.add_device_key(key).await,
            ServerStorage::Database(db) => db.add_device_key(key).await,
        }
    }

    async fn remove_device_key(&self, key: &DevicePublicKey) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => fs.remove_device_key(key).await,
            ServerStorage::Database(db) => db.remove_device_key(key).await,
        }
    }

    async fn get_vault(&self, vault_id: &VaultId) -> Result<Option<Vault>> {
        match self {
            ServerStorage::FileSystem(fs) => fs.get_vault(vault_id).await,
            ServerStorage::Database(db) => db.get_vault(vault_id).await,
        }
    }

    async fn put_vault(&self, vault: Vault) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => fs.put_vault(vault).await,
            ServerStorage::Database(db) => db.put_vault(vault).await,
        }
    }

    async fn delete_vault(&self, vault_id: &VaultId) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => fs.delete_vault(vault_id).await,
            ServerStorage::Database(db) => db.delete_vault(vault_id).await,
        }
    }

    async fn list_vaults(&self) -> Result<Vec<VaultId>> {
        match self {
            ServerStorage::FileSystem(fs) => fs.list_vaults().await,
            ServerStorage::Database(db) => db.list_vaults().await,
        }
    }

    async fn get_secret(&self, vault_id: &VaultId, secret_id: &SecretId) -> Result<Option<Secret>> {
        match self {
            ServerStorage::FileSystem(fs) => fs.get_secret(vault_id, secret_id).await,
            ServerStorage::Database(db) => db.get_secret(vault_id, secret_id).await,
        }
    }

    async fn put_secret(&self, vault_id: &VaultId, secret: Secret) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => fs.put_secret(vault_id, secret).await,
            ServerStorage::Database(db) => db.put_secret(vault_id, secret).await,
        }
    }

    async fn delete_secret(&self, vault_id: &VaultId, secret_id: &SecretId) -> Result<()> {
        match self {
            ServerStorage::FileSystem(fs) => fs.delete_secret(vault_id, secret_id).await,
            ServerStorage::Database(db) => db.delete_secret(vault_id, secret_id).await,
        }
    }

    async fn list_secrets(&self, vault_id: &VaultId) -> Result<Vec<SecretId>> {
        match self {
            ServerStorage::FileSystem(fs) => fs.list_secrets(vault_id).await,
            ServerStorage::Database(db) => db.list_secrets(vault_id).await,
        }
    }
}
