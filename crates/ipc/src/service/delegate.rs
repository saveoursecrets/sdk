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
pub type LocalAccountServiceDelegate = ServiceDelegate<
    <LocalAccount as Account>::Error,
    <LocalAccount as Account>::NetworkResult,
    LocalAccount,
>;

/// Service delegate for network-enabled accounts.
pub type NetworkAccountServiceDelegate = ServiceDelegate<
    <NetworkAccount as Account>::Error,
    <NetworkAccount as Account>::NetworkResult,
    NetworkAccount,
>;

/// Command to authenticate an account.
pub struct AuthenticateCommand<E, R, A>
where
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
    R: 'static,
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
{
    /// Account address.
    pub address: Address,
    /// Collection of accounts.
    pub accounts: Arc<RwLock<AccountSwitcher<E, R, A>>>,
    /// Result channel for the outcome.
    pub result: oneshot::Sender<CommandOutcome>,
}

/// Command to lock an account.
pub struct LockCommand<E, R, A>
where
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
    R: 'static,
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
{
    /// Account address.
    pub address: Address,
    /// Collection of accounts.
    pub accounts: Arc<RwLock<AccountSwitcher<E, R, A>>>,
    /// Result channel for the outcome.
    pub result: oneshot::Sender<CommandOutcome>,
}

/// Collection of command receivers for service delegates.
pub struct CommandDelegate<E, R, A>
where
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
    R: 'static,
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
{
    /// Receiver for authenticate commands.
    pub authenticate: mpsc::Receiver<AuthenticateCommand<E, R, A>>,

    /// Receiver for lock commands.
    pub lock: mpsc::Receiver<LockCommand<E, R, A>>,
}

/// Delegate for service requests.
///
/// Create a delegate by calling [NetworkAccountIpcService::new_delegate] or [LocalAccountIpcService::new_delegate].
///
/// When delegates receive a message on the authenticate channel
/// they MUST reply on the [AuthenticateCommand::result] sender
/// with an [CommandOutcome].
pub struct ServiceDelegate<E, R, A>
where
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
    R: 'static,
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
{
    pub(super) authenticate: mpsc::Sender<AuthenticateCommand<E, R, A>>,
    pub(super) lock: mpsc::Sender<LockCommand<E, R, A>>,
}

impl<E, R, A> ServiceDelegate<E, R, A>
where
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
    R: 'static,
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
{
    /// Create a new service delegate.
    pub fn new(
        buffer: usize,
    ) -> (ServiceDelegate<E, R, A>, CommandDelegate<E, R, A>) {
        let (authenticate_tx, authenticate_rx) =
            mpsc::channel::<AuthenticateCommand<E, R, A>>(buffer);

        let (lock_tx, lock_rx) =
            mpsc::channel::<LockCommand<E, R, A>>(buffer);

        let service = ServiceDelegate {
            authenticate: authenticate_tx,
            lock: lock_tx,
        };

        let command = CommandDelegate {
            authenticate: authenticate_rx,
            lock: lock_rx,
        };

        (service, command)
    }
}
