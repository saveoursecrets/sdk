//! Sync types, traits and merge implementations
//! for local account and folders.
mod folder;
mod local_account;
mod primitives;
mod transport;

#[cfg(feature = "files")]
mod transfer;

#[cfg(feature = "files")]
pub use transfer::*;

pub use primitives::*;
pub use transport::*;

pub(crate) use folder::{FolderMerge, IdentityFolderMerge};
