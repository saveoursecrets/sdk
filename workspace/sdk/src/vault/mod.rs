//! Vault secret storage file format.

mod file_access;
mod gatekeeper;
pub mod secret;
mod vault;

pub use file_access::VaultFileAccess;
pub use gatekeeper::Gatekeeper;
pub use vault::{
    Header, Summary, Vault, VaultAccess, VaultCommit, VaultEntry, VaultFlags,
    VaultId, VaultRef,
};

pub(crate) use vault::Contents;
