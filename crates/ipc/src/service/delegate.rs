use crate::AuthenticateOutcome;
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
    pub result: oneshot::Sender<AuthenticateOutcome>,
}

/// Handler for authenticate requests.
pub type AuthenticateHandler<E, R, A> =
    mpsc::Sender<AuthenticateCommand<E, R, A>>;

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
}

/// Delegate for service requests.
///
/// Create a delegate by calling [NetworkAccountIpcService::new_delegate] or [LocalAccountIpcService::new_delegate].
///
/// When delegates receive a message on the authenticate channel
/// they MUST reply on the [AuthenticateCommand::result] sender
/// with an [AuthenticateOutcome].
pub struct ServiceDelegate<E, R, A>
where
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
    R: 'static,
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
{
    pub(super) authenticate: AuthenticateHandler<E, R, A>,
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

        let service = ServiceDelegate {
            authenticate: authenticate_tx,
        };

        let command = CommandDelegate {
            authenticate: authenticate_rx,
        };

        (service, command)
    }
}
