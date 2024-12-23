//! Network aware account storage.
use crate::sdk::prelude::{Account, AccountSwitcher};

// mod auto_merge;
#[cfg(feature = "files")]
mod file_transfers;
#[cfg(feature = "listen")]
mod listen;
mod network_account;
mod remote;
mod sync;

/// Account switcher for network-enabled accounts.
pub type NetworkAccountSwitcher = AccountSwitcher<
    NetworkAccount,
    <NetworkAccount as Account>::NetworkResult,
    <NetworkAccount as Account>::Error,
>;

#[cfg(feature = "files")]
pub use file_transfers::{
    CancelChannel, FileTransferSettings, InflightNotification,
    InflightRequest, InflightTransfers, TransferError,
};
pub use network_account::{NetworkAccount, NetworkAccountOptions};
pub use remote::RemoteBridge;
