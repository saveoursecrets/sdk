//! Sync types, traits and merge implementations
//! for local account and folders.

mod auto_merge;
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

pub use auto_merge::*;
pub use primitives::*;
pub use remote::*;
pub use transport::*;

pub(crate) use folder::{FolderMerge, IdentityFolderMerge};
