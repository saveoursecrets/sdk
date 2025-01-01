//! Sync types, traits and merge implementations
//! for local account and folders.

mod auto_merge;
mod primitives;
mod remote;

pub use auto_merge::*;
pub use primitives::*;
pub use remote::*;

/// Direction of a sync.
#[derive(Debug, Clone, Copy)]
pub enum SyncDirection {
    /// Create accounts on remote from the local.
    ///
    /// Used when a local account is pushing data to
    /// a server for syncing with other devices.
    Push,
    /// Create accounts on local from the remote.
    ///
    /// Used by local replicas for app integrations
    /// such as the browser extension.
    Pull,
}
