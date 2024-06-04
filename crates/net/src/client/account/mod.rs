//! Network aware account storage.

#[cfg(feature = "files")]
mod file_transfers;
#[cfg(feature = "listen")]
mod listen;
mod network_account;
mod remote;
mod sync;

/// Information about a cancellation.
#[derive(Default, Debug, Clone, Hash, Eq, PartialEq)]
pub enum CancelReason {
    /// Unknown reason.
    #[default]
    Unknown,
    /// Event loop is being shutdown.
    Shutdown,
    /// Websocket connection was closed.
    Closed,
    /// Cancellation was from a user interaction.
    UserCanceled,
    /// Aborted due to conflict with a subsequent operation.
    ///
    /// For example, a move or delete transfer operation must abort
    /// any existing upload or download.
    Aborted,
}

#[cfg(feature = "files")]
pub use file_transfers::{
    CancelChannel, FileTransferSettings, InflightNotification,
    InflightRequest, InflightTransfers, ProgressChannel, TransferError,
};
pub use network_account::{NetworkAccount, NetworkAccountOptions};
pub use remote::RemoteBridge;
