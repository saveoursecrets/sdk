#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Vault encrypted storage and access.
mod builder;
mod change;
mod encoding;
mod error;
mod file_writer;
mod gatekeeper;
pub mod secret;
mod vault;

// mod reducer;
// pub use reducer::FolderReducer;

// mod folder;
// pub use folder::{DiscFolder, Folder, MemoryFolder};

pub use builder::{BuilderCredentials, VaultBuilder};
pub use change::ChangePassword;
pub use error::Error;
pub use file_writer::VaultWriter;
pub use gatekeeper::Gatekeeper;
pub use vault::{
    FolderRef, Header, SharedAccess, Summary, Vault, VaultAccess, VaultMeta,
};

pub use sos_core::{VaultCommit, VaultEntry, VaultFlags, VaultId};

pub(crate) type Result<T> = std::result::Result<T, Error>;

pub(crate) use vault::Auth;

#[cfg(debug_assertions)]
#[doc(hidden)]
pub use vault::Contents;

#[cfg(not(debug_assertions))]
pub(crate) use vault::Contents;
