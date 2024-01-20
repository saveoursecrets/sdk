//! Vault secret storage.

mod builder;
mod file_writer;
mod gatekeeper;
pub mod secret;
mod vault;

pub use builder::VaultBuilder;
pub use file_writer::VaultWriter;
pub use gatekeeper::Gatekeeper;
pub use vault::{
    FolderRef, Header, SharedAccess, Summary, Vault, VaultAccess,
    VaultCommit, VaultEntry, VaultFlags, VaultId, VaultMeta,
};

pub(crate) use vault::{Auth, Contents};
