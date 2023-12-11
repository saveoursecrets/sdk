//! Types and traits for synchronization.

use crate::{signer::ecdsa::Address, vault::VaultId};
use std::collections::HashMap;

mod patch;

pub use patch::{AccountPatch, FolderPatch, Patch};

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
    /// Folders to be imported into the new account.
    pub folders: HashMap<VaultId, FolderPatch>,
}
