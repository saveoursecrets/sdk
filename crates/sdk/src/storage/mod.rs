//! Folder storage backed by the file system.
use crate::{
    crypto::{AccessKey, Cipher, KeyDerivation},
    events::{AccountEventLog, FolderEventLog},
    signer::ecdsa::Address,
    vault::{Summary, Vault, VaultFlags, VaultId},
    Result,
};
use async_trait::async_trait;
use indexmap::IndexSet;
use std::{path::Path, sync::Arc};
use tokio::sync::RwLock;

mod client;
#[cfg(feature = "files")]
pub mod files;
mod folder;
pub(crate) mod paths;
#[cfg(feature = "search")]
pub mod search;

pub use client::ClientStorage;
pub use folder::{DiscFolder, Folder, MemoryFolder};

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use paths::FileLock;

use crate::events::DeviceEventLog;

#[cfg(feature = "files")]
use crate::{events::FileEventLog, storage::files::ExternalFile};

/// Options used when creating a new folder.
#[derive(Debug, Default)]
pub struct NewFolderOptions {
    /// Flags for the new folder.
    pub flags: VaultFlags,
    /// Access key.
    pub key: Option<AccessKey>,
    /// Encryption cipher.
    pub cipher: Option<Cipher>,
    /// Key derivation function.
    pub kdf: Option<KeyDerivation>,
}

/// Collection of vaults for an account.
#[derive(Default)]
pub struct AccountPack {
    /// Address of the account.
    pub address: Address,
    /// Identity vault.
    pub identity_vault: Vault,
    /// Addtional folders to be imported
    /// into the new account.
    pub folders: Vec<Vault>,
}

/// Options used when accessing account data.
#[derive(Default, Clone)]
pub struct AccessOptions {
    /// Target folder for the operation.
    ///
    /// If no target folder is given the current open folder
    /// will be used. When no folder is open and the target
    /// folder is not given an error will be returned.
    pub folder: Option<Summary>,
    /// Channel for file progress operations.
    #[cfg(feature = "files")]
    pub file_progress: Option<tokio::sync::mpsc::Sender<files::FileProgress>>,
}

impl From<Summary> for AccessOptions {
    fn from(value: Summary) -> Self {
        Self {
            folder: Some(value),
            #[cfg(feature = "files")]
            file_progress: None,
        }
    }
}

/// Compute the file name from a path.
///
/// If no file name is available the returned value is the
/// empty string.
pub fn basename(path: impl AsRef<Path>) -> String {
    path.as_ref()
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// Guess the MIME type of a path.
///
/// This implementation supports some more types
/// that are not in the the mime_guess library that
/// we also want to recognize.
pub fn guess_mime(path: impl AsRef<Path>) -> Result<String> {
    if let Some(extension) = path.as_ref().extension() {
        let fixed = match extension.to_string_lossy().as_ref() {
            "heic" => Some("image/heic".to_string()),
            "heif" => Some("image/heif".to_string()),
            "avif" => Some("image/avif".to_string()),
            _ => None,
        };

        if let Some(fixed) = fixed {
            return Ok(fixed);
        }
    }
    let mime = mime_guess::from_path(&path)
        .first_or(mime_guess::mime::APPLICATION_OCTET_STREAM)
        .to_string();
    Ok(mime)
}

/// References to the storage event logs.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait StorageEventLogs {
    /// Clone of the identity log.
    async fn identity_log(&self) -> Result<Arc<RwLock<FolderEventLog>>>;

    /// Clone of the account log.
    async fn account_log(&self) -> Result<Arc<RwLock<AccountEventLog>>>;

    /// Clone of the device log.
    async fn device_log(&self) -> Result<Arc<RwLock<DeviceEventLog>>>;

    /// Clone of the file log.
    #[cfg(feature = "files")]
    async fn file_log(&self) -> Result<Arc<RwLock<FileEventLog>>>;

    /// Canonical collection of files reduced from the file event log.
    #[cfg(feature = "files")]
    async fn canonical_files(&self) -> Result<IndexSet<ExternalFile>> {
        use crate::events::FileReducer;
        let files = self.file_log().await?;
        let event_log = files.read().await;

        // Canonical list of external files.
        let reducer = FileReducer::new(&event_log);
        Ok(reducer.reduce(None).await?)
    }

    /// Folder identifiers managed by this storage.
    async fn folder_identifiers(&self) -> Result<IndexSet<VaultId>>;

    /// Folder information managed by this storage.
    async fn folder_details(&self) -> Result<IndexSet<Summary>>;

    /// Folder event log.
    async fn folder_log(
        &self,
        id: &VaultId,
    ) -> Result<Arc<RwLock<FolderEventLog>>>;
}
