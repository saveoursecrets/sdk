//! Sync types, traits and merge implementations
//! for local account and folders.
mod folder;
mod local_account;
mod primitives;

#[cfg(feature = "files")]
mod transfer;

#[cfg(feature = "files")]
pub use transfer::*;

pub use primitives::*;

pub(crate) use folder::{FolderMerge, IdentityFolderMerge};
