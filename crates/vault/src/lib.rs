#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Vault encrypted storage and access.
mod builder;
mod change;
mod encoding;
mod error;
mod gatekeeper;
pub mod secret;
mod vault;

pub use builder::{BuilderCredentials, VaultBuilder};
pub use change::ChangePassword;
pub use error::Error;
pub use gatekeeper::GateKeeper;
pub use vault::{
    FolderRef, Header, SharedAccess, Summary, Vault, VaultAccess, VaultMeta,
};

// DO NOT USE: these re-exports will be removed in the future
pub use sos_core::{VaultCommit, VaultEntry, VaultFlags, VaultId};

pub(crate) type Result<T> = std::result::Result<T, Error>;

pub(crate) use vault::Auth;

#[cfg(debug_assertions)]
#[doc(hidden)]
pub use vault::Contents;

#[cfg(not(debug_assertions))]
pub(crate) use vault::Contents;
