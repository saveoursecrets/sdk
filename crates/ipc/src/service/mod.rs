use crate::{io_err, AccountsList, IpcRequest, IpcResponse, IpcResponseBody};
use async_trait::async_trait;
use sos_net::{
    sdk::{
        account::{Account, AccountSwitcher, LocalAccount},
        prelude::Identity,
        Paths,
    },
    NetworkAccount,
};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

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
    delegate: mpsc::Sender<Command<E, R, A>>,
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
        delegate: mpsc::Sender<Command<E, R, A>>,
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
            IpcRequest::Status => {
                let paths = Paths::new_global(Paths::data_dir()?);
                let app = paths.has_app_lock()?;
                Ok(IpcResponse::Value(IpcResponseBody::Status {
                    app,
                    ipc: true,
                }))
            }
            IpcRequest::Ping => Ok(IpcResponse::Value(IpcResponseBody::Pong)),
            IpcRequest::OpenUrl(_) => {
                // Open is a noop as we let the native bridge handle it
                Ok(IpcResponse::Value(IpcResponseBody::OpenUrl(false)))
            }
            IpcRequest::ListAccounts => {
                let data = self.list_accounts().await?;
                Ok(IpcResponse::Value(IpcResponseBody::Accounts(data)))
            }
            IpcRequest::Authenticate { address } => {
                let (result, result_rx) = tokio::sync::oneshot::channel();
                let command = Command {
                    accounts: self.accounts.clone(),
                    options: CommandOptions::Authenticate { address, result },
                };
                match self.delegate.send(command).await {
                    Ok(_) => match result_rx.await {
                        Ok(outcome) => Ok(IpcResponse::Value(
                            IpcResponseBody::Authenticate(outcome),
                        )),
                        Err(err) => Err(io_err(err).into()),
                    },
                    Err(err) => Err(io_err(err).into()),
                }
            }
            IpcRequest::Lock { address } => {
                let (result, result_rx) = tokio::sync::oneshot::channel();
                let command = Command {
                    accounts: self.accounts.clone(),
                    options: CommandOptions::Lock { address, result },
                };
                match self.delegate.send(command).await {
                    Ok(_) => match result_rx.await {
                        Ok(outcome) => Ok(IpcResponse::Value(
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
