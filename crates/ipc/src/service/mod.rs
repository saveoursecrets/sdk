use crate::{io_err, AccountsList, IpcRequest, IpcResponse, IpcResponseBody};
use async_trait::async_trait;
use sos_net::{
    sdk::{
        account::{Account, AccountSwitcher, LocalAccount},
        prelude::Identity,
    },
    NetworkAccount,
};
use std::sync::Arc;
use tokio::sync::RwLock;

mod delegate;
pub use delegate::*;

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

/// Service handler called by servers.
///
/// Some requests are delegated to a service delegate as they
/// may need to get input from the user and how that is done
/// will vary for each application.
#[async_trait]
pub trait IpcService<E> {
    /// Handle a request and reply with a response.
    async fn handle(
        &self,
        request: IpcRequest,
    ) -> std::result::Result<IpcResponse, E>;
}

/// Handler for IPC requests.
pub struct IpcServiceHandler<E, R, A>
where
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
    R: 'static,
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
{
    accounts: Arc<RwLock<AccountSwitcher<E, R, A>>>,
    delegate: ServiceDelegate<E, R, A>,
}

impl<E, R, A> IpcServiceHandler<E, R, A>
where
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
    R: 'static,
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
{
    /// Create a new service handler.
    pub fn new(
        accounts: Arc<RwLock<AccountSwitcher<E, R, A>>>,
        delegate: ServiceDelegate<E, R, A>,
    ) -> Self {
        Self { accounts, delegate }
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
impl<E, R, A> IpcService<E> for IpcServiceHandler<E, R, A>
where
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
    R: 'static,
    A: Account<Error = E, NetworkResult = R> + Sync + Send + 'static,
{
    /// Handle an incoming request.
    async fn handle(
        &self,
        request: IpcRequest,
    ) -> std::result::Result<IpcResponse, E> {
        match request {
            IpcRequest::ListAccounts => {
                let data = self.list_accounts().await?;
                Ok(IpcResponse::Body(IpcResponseBody::Accounts(data)))
            }
            IpcRequest::Authenticate { address } => {
                let (result_tx, result_rx) = tokio::sync::oneshot::channel();
                let command = AuthenticateCommand {
                    address,
                    accounts: self.accounts.clone(),
                    result: result_tx,
                };
                match self.delegate.authenticate.send(command).await {
                    Ok(_) => match result_rx.await {
                        Ok(outcome) => Ok(IpcResponse::Body(
                            IpcResponseBody::Authenticate(outcome),
                        )),
                        Err(err) => Err(io_err(err).into()),
                    },
                    Err(err) => Err(io_err(err).into()),
                }
            }
            IpcRequest::Lock { address } => {
                let (result_tx, result_rx) = tokio::sync::oneshot::channel();
                let command = LockCommand {
                    address,
                    accounts: self.accounts.clone(),
                    result: result_tx,
                };
                match self.delegate.lock.send(command).await {
                    Ok(_) => match result_rx.await {
                        Ok(outcome) => Ok(IpcResponse::Body(
                            IpcResponseBody::Lock(outcome),
                        )),
                        Err(err) => Err(io_err(err).into()),
                    },
                    Err(err) => Err(io_err(err).into()),
                }
            }
        }
    }
}
