#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Client storage backed by the file system.
use sos_core::{
    crypto::{AccessKey, Cipher, KeyDerivation},
    events::WriteEvent,
    AccountId, VaultId,
};
use sos_vault::{Vault, VaultFlags};

mod database;
mod error;
#[cfg(feature = "files")]
pub mod files;
mod filesystem;
pub(crate) mod folder_sync;
mod secret_storage;
mod storage;
mod sync;
mod traits;

pub use error::Error;
pub use storage::ClientStorage;
pub use traits::{
    ClientAccountStorage, ClientBaseStorage, ClientDeviceStorage,
    ClientFolderStorage, ClientSecretStorage,
};
pub(crate) use traits::{ClientEventLogStorage, ClientVaultStorage};

/// Result type for the client module.
pub(crate) type Result<T> = std::result::Result<T, Error>;

#[cfg(feature = "files")]
use sos_external_files::FileMutationEvent;

/// Options used when creating a new folder.
#[derive(Debug, Default)]
pub struct NewFolderOptions {
    /// Folder name.
    pub name: String,
    /// Flags for the new folder.
    pub flags: Option<VaultFlags>,
    /// Access key.
    pub key: Option<AccessKey>,
    /// Encryption cipher.
    pub cipher: Option<Cipher>,
    /// Key derivation function.
    pub kdf: Option<KeyDerivation>,
}

impl NewFolderOptions {
    /// Create new folder options.
    pub fn new(name: String) -> Self {
        Self {
            name,
            flags: None,
            key: None,
            cipher: None,
            kdf: None,
        }
    }
}

/// Collection of vaults for an account.
#[derive(Default)]
pub struct AccountPack {
    /// Address of the account.
    pub account_id: AccountId,
    /// Identity vault.
    pub identity_vault: Vault,
    /// Addtional folders to be imported
    /// into the new account.
    pub folders: Vec<Vault>,
}

/// Options used when accessing account data.
#[derive(Default, Clone)]
pub struct AccessOptions {
    /// Source folder for the operation.
    ///
    /// If no target folder is given the current open folder
    /// will be used; it is an error if there is neither a
    /// target folder or a currently open folder.
    pub folder: Option<VaultId>,

    /// Destination folder for the operation.
    ///
    /// Use during update operations to allow secrets
    /// to be moved to a different folder.
    pub destination: Option<VaultId>,

    /// Channel for file progress operations.
    #[cfg(feature = "files")]
    pub file_progress:
        Option<tokio::sync::mpsc::Sender<sos_external_files::FileProgress>>,
}

impl From<&VaultId> for AccessOptions {
    fn from(value: &VaultId) -> Self {
        Self {
            folder: Some(*value),
            destination: None,
            #[cfg(feature = "files")]
            file_progress: None,
        }
    }
}

/// Storage change event with an optional
/// collection of file mutation events.
#[doc(hidden)]
pub struct StorageChangeEvent {
    /// Write event.
    pub event: WriteEvent,
    /// Collection of file mutation events.
    #[cfg(feature = "files")]
    pub file_events: Vec<FileMutationEvent>,
}
