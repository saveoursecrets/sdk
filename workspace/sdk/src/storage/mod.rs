//! Folder storage backed by the file system.
use crate::{
    commit::{CommitProof, CommitState},
    signer::ecdsa::Address,
    vault::{Summary, Vault, VaultId},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::mpsc;

#[cfg(feature = "files")]
pub mod files;
pub(crate) mod paths;
#[cfg(feature = "search")]
pub mod search;
mod storage;
#[cfg(feature = "sync")]
mod sync;

pub use storage::{Folder, Storage};

#[cfg(feature = "sync")]
use crate::sync::{AccountPatch, FolderPatch};

/// Collection of vaults for an account.
#[derive(Default)]
pub struct AccountPack {
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
