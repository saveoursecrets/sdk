use crate::CommandOutcome;
use sos_net::{
    sdk::{
        account::Account,
        prelude::{AccountSwitcher, Address, LocalAccount},
    },
    NetworkAccount,
};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, RwLock};

/// Service delegate for local accounts.
pub type LocalAccountServiceDelegate = mpsc::Sender<
    Command<
        <LocalAccount as Account>::Error,
        <LocalAccount as Account>::NetworkResult,
        LocalAccount,
    >,
>;

/// Service delegate for network-enabled accounts.
pub type NetworkAccountServiceDelegate = mpsc::Sender<
    Command<
        <NetworkAccount as Account>::Error,
        <NetworkAccount as Account>::NetworkResult,
        NetworkAccount,
    >,
>;

/// Command for local accounts.
pub type LocalAccountCommand = Command<
    <LocalAccount as Account>::Error,
    <LocalAccount as Account>::NetworkResult,
    LocalAccount,
>;

/// Command for network-enabled accounts.
pub type NetworkAccountCommand = Command<
    <NetworkAccount as Account>::Error,
    <NetworkAccount as Account>::NetworkResult,
    NetworkAccount,
>;

/// Command sent to delegates.
///
/// When a delegate receives a command it MUST reply
/// on the `result` channel in the command options.
pub struct Command<E, R, A>
where
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
    R: 'static,
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
{
    /// Collection of accounts.
    pub accounts: Arc<RwLock<AccountSwitcher<E, R, A>>>,
    /// Options for the command.
    pub options: CommandOptions,
}

/// Options for a command.
pub enum CommandOptions {
    /// Options to authenticate an account.
    Authenticate {
        /// Account address.
        address: Address,
        /// Result channel for the outcome.
        result: oneshot::Sender<CommandOutcome>,
    },
    /// Options to lock an account.
    Lock {
        /// Account address.
        ///
        /// When no account address is given the delegate should
        /// lock all authenticated accounts.
        address: Option<Address>,
        /// Result channel for the outcome.
        result: oneshot::Sender<CommandOutcome>,
    },
}

/// Create a delegate channel for local accounts.
pub fn local_account_delegate(
    buffer: usize,
) -> (
    mpsc::Sender<
        Command<
            <LocalAccount as Account>::Error,
            <LocalAccount as Account>::NetworkResult,
            LocalAccount,
        >,
    >,
    mpsc::Receiver<
        Command<
            <LocalAccount as Account>::Error,
            <LocalAccount as Account>::NetworkResult,
            LocalAccount,
        >,
    >,
) {
    mpsc::channel(buffer)
}

/// Create a delegate channel for network-enabled accounts.
pub fn network_account_delegate(
    buffer: usize,
) -> (
    mpsc::Sender<
        Command<
            <NetworkAccount as Account>::Error,
            <NetworkAccount as Account>::NetworkResult,
            NetworkAccount,
        >,
    >,
    mpsc::Receiver<
        Command<
            <NetworkAccount as Account>::Error,
            <NetworkAccount as Account>::NetworkResult,
            NetworkAccount,
        >,
    >,
) {
    mpsc::channel(buffer)
}
