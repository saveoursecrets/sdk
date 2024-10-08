//! Vault encrypted storage and access.

mod builder;
mod file_writer;
mod gatekeeper;
pub mod secret;
mod vault;

pub use builder::{BuilderCredentials, VaultBuilder};
pub use file_writer::VaultWriter;
pub use gatekeeper::Gatekeeper;
pub use vault::{
    FolderRef, Header, SharedAccess, Summary, Vault, VaultAccess,
    VaultCommit, VaultEntry, VaultFlags, VaultId, VaultMeta,
};

pub(crate) use vault::Auth;

#[cfg(debug_assertions)]
#[doc(hidden)]
pub use vault::Contents;

#[cfg(not(debug_assertions))]
pub(crate) use vault::Contents;
