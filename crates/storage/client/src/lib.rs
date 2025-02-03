#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Client storage backed by the file system.
use sos_core::{
    crypto::{AccessKey, Cipher, KeyDerivation},
    AccountId,
};
use sos_vault::{Summary, Vault, VaultFlags};

mod error;
#[cfg(feature = "files")]
pub mod files;
mod filesystem;
mod traits;

pub use error::Error;
pub use filesystem::ClientStorage;
pub use traits::ClientAccountStorage;

/// Result type for the client module.
pub(crate) type Result<T> = std::result::Result<T, Error>;

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
    /// Target folder for the operation.
    ///
    /// If no target folder is given the current open folder
    /// will be used. When no folder is open and the target
    /// folder is not given an error will be returned.
    pub folder: Option<Summary>,
    /// Channel for file progress operations.
    #[cfg(feature = "files")]
    pub file_progress:
        Option<tokio::sync::mpsc::Sender<sos_external_files::FileProgress>>,
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
