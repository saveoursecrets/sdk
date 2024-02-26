//! Network aware account storage.

#[cfg(feature = "listen")]
mod listen;
mod network_account;
mod remote;
mod sync;

pub use network_account::NetworkAccount;
pub use remote::RemoteBridge;

/// Determine if the offline environment variable is set.
pub fn is_offline() -> bool {
    std::env::var("SOS_OFFLINE").ok().is_some()
}
