//! Types and traits for synchronization.

use crate::signer::ecdsa::Address;

mod patch;

pub use patch::{Patch, AccountPatch, FolderPatch};

#[cfg(feature = "files")]
pub use patch::FilePatch;

/// Collection of patches for an account.
#[derive(Default)]
pub struct ChangeSet {
    /// Address of the account signing key.
    pub address: Address,
    /// Identity vault event logs.
    pub identity: FolderPatch,
    /// Account event logs.
    pub account: AccountPatch,
    /// Addtional folders to be imported
    /// into the new account.
    pub folders: Vec<FolderPatch>,
}

