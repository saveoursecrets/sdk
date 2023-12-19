//! Folder storage backed by the file system.
use crate::{vault::{Summary, Vault}, signer::ecdsa::Address};
use tokio::sync::mpsc;

mod client;
#[cfg(feature = "files")]
pub mod files;
mod folder;
pub(crate) mod paths;
#[cfg(feature = "search")]
pub mod search;
mod server;
#[cfg(feature = "sync")]
pub(crate) mod sync;

pub use client::ClientStorage;
pub use folder::{DiscFolder, Folder, MemoryFolder};
pub use server::ServerStorage;

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
    pub file_progress: Option<mpsc::Sender<files::FileProgress>>,
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
