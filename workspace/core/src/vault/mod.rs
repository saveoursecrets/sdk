//! Vault secret storage file format.

mod file_access;
mod gatekeeper;
pub mod secret;
#[allow(clippy::module_inception)]
mod vault;

pub use file_access::VaultFileAccess;
pub use gatekeeper::Gatekeeper;
pub use vault::{
    Header, Summary, Vault, VaultAccess, VaultCommit, VaultEntry, VaultFlags,
    VaultId,
};

pub(crate) use vault::Contents;
