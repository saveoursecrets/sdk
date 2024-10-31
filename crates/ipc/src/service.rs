use crate::{AccountsList, AuthenticateOutcome, IpcRequest, IpcResponse};
use async_trait::async_trait;
use sos_net::{
    sdk::{
        account::{Account, AccountSwitcher, LocalAccount},
        prelude::{Address, Identity},
    },
    NetworkAccount,
};
use std::sync::Arc;
use tokio::sync::RwLock;

/// IPC service for local accounts.
pub type LocalAccountIpcService = IpcServiceHandler<
    <LocalAccount as Account>::Error,
    <LocalAccount as Account>::NetworkResult,
    LocalAccount,
>;

/// IPC service for network-enabled accounts.
pub type NetworkAccountIpcService = IpcServiceHandler<
    <NetworkAccount as Account>::Error,
    <NetworkAccount as Account>::NetworkResult,
    NetworkAccount,
>;

/// Authenticate command for local accounts.
pub type LocalAccountAuthenticateCommand = AuthenticateCommand<
    <LocalAccount as Account>::Error,
    <LocalAccount as Account>::NetworkResult,
    LocalAccount,
>;

/// Authenticate command for network-enabled accounts.
pub type NetworkAccountAuthenticateCommand = AuthenticateCommand<
    <NetworkAccount as Account>::Error,
    <NetworkAccount as Account>::NetworkResult,
    NetworkAccount,
>;

/// Command to authenticate an account.
pub struct AuthenticateCommand<E, R, A>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    E: From<sos_net::sdk::Error>,
{
    /// Account address.
    pub address: Address,
    /// Collection of accounts.
    pub accounts: Arc<RwLock<AccountSwitcher<E, R, A>>>,
    /// Result channel for the outcome.
    pub result: tokio::sync::oneshot::Sender<AuthenticateOutcome>,
}

/// Handler for authenticate requests.
pub type AuthenticateHandler<E, R, A> =
    tokio::sync::mpsc::Sender<AuthenticateCommand<E, R, A>>;

/// Service handler for IPC requests
#[async_trait]
pub trait IpcService<E> {
    /// Handle a request and reply with a response.
    async fn handle(
        &mut self,
        request: IpcRequest,
    ) -> std::result::Result<IpcResponse, E>;
}

pub struct IpcServiceHandler<E, R, A>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    E: From<sos_net::sdk::Error>,
{
    accounts: Arc<RwLock<AccountSwitcher<E, R, A>>>,
    authenticate_handler: AuthenticateHandler<E, R, A>,
}

impl<E, R, A> IpcServiceHandler<E, R, A>
where
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
    E: From<sos_net::sdk::Error>,
{
    pub fn new(
        accounts: Arc<RwLock<AccountSwitcher<E, R, A>>>,
        authenticate_handler: AuthenticateHandler<E, R, A>,
    ) -> Self {
        Self {
            accounts,
            authenticate_handler,
        }
    }

    async fn list_accounts(&self) -> std::result::Result<AccountsList, E> {
        let accounts = self.accounts.read().await;
        let mut out = Vec::new();
        let disc_accounts =
            Identity::list_accounts(accounts.data_dir()).await?;
        for account in disc_accounts {
            let authenticated = if let Some(memory_account) =
                accounts.iter().find(|a| a.address() == account.address())
            {
                memory_account.is_authenticated().await
            } else {
                false
            };

            out.push((account, authenticated));
        }
        Ok(out)
    }
}

#[async_trait]
impl<E, R, A: Account<Error = E, NetworkResult = R> + Send + Sync>
    IpcService<E> for IpcServiceHandler<E, R, A>
where
    E: std::fmt::Debug + From<sos_net::sdk::Error>,
{
    /// Handle an incoming request.
    async fn handle(
        &mut self,
        request: IpcRequest,
    ) -> std::result::Result<IpcResponse, E> {
        Ok(match request {
            IpcRequest::ListAccounts => {
                let data = self.list_accounts().await?;
                IpcResponse::ListAccounts(data)
            }
            IpcRequest::Authenticate { address } => {
                let (result_tx, result_rx) = tokio::sync::oneshot::channel();
                let command = AuthenticateCommand {
                    address,
                    accounts: self.accounts.clone(),
                    result: result_tx,
                };
                match self.authenticate_handler.send(command).await {
                    Ok(_) => match result_rx.await {
                        Ok(outcome) => IpcResponse::Authenticate(outcome),
                        Err(err) => todo!("handle authenticate send error"),
                    },
                    Err(err) => todo!("handle authenticate receive error"),
                }
            }
        })
    }
}
