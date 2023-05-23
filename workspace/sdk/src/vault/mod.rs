//! Vault secret storage file format.

mod file_writer;
mod gatekeeper;
pub mod secret;
mod vault;

pub use file_writer::VaultWriter;
pub use gatekeeper::Gatekeeper;
pub use vault::{
    Header, Summary, Vault, VaultAccess, VaultCommit, VaultEntry, VaultFlags,
    VaultId, VaultMeta, VaultRef,
};

pub(crate) use vault::Contents;
