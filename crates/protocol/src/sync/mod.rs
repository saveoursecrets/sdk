//! Sync types, traits and merge implementations
//! for local account and folders.

mod folder;
#[cfg(feature = "account")]
mod local_account;
mod primitives;
mod remote;
mod transport;

#[cfg(feature = "files")]
mod transfer;

#[cfg(feature = "files")]
pub use transfer::*;

pub use primitives::*;
pub use remote::*;
pub use transport::*;

pub(crate) use folder::{FolderMerge, IdentityFolderMerge};
