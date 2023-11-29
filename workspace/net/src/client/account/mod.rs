//! Network aware account storage.

#[cfg(feature = "archive")]
mod archive;
#[cfg(feature = "contacts")]
mod contacts;
#[cfg(feature = "device")]
mod device;
#[cfg(feature = "listen")]
mod listen;
mod macros;
#[cfg(feature = "migrate")]
mod migrate;
mod network_account;
mod remote;
#[cfg(feature = "security-report")]
mod security_report;
mod sync;

#[cfg(feature = "device")]
pub use device::DeviceManager;

pub use network_account::NetworkAccount;
pub use remote::{Origin, Remote, RemoteBridge, Remotes};
