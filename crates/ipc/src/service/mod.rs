use crate::{
    io_err, AccountsList, IpcRequest, IpcRequestBody, IpcResponse,
    IpcResponseBody, SearchResults,
};
use async_trait::async_trait;
use sos_net::{
    sdk::{
        account::{Account, AccountSwitcher, LocalAccount},
        prelude::{ArchiveFilter, DocumentView, Identity, QueryFilter},
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

    async fn search(
        &self,
        needle: String,
        filter: QueryFilter,
    ) -> std::result::Result<SearchResults, E> {
        let mut out = Vec::new();
        let accounts = self.accounts.read().await;
        for account in accounts.iter() {
            if account.is_authenticated().await {
                let identity = account.public_identity().await?;
                let results =
                    account.query_map(&needle, filter.clone()).await?;
                out.push((identity, results));
            }
        }
        Ok(out)
    }

    async fn query_view(
        &self,
        views: &[DocumentView],
        archive_filter: Option<&ArchiveFilter>,
    ) -> std::result::Result<SearchResults, E> {
        let mut out = Vec::new();
        let accounts = self.accounts.read().await;
        for account in accounts.iter() {
            if account.is_authenticated().await {
                let identity = account.public_identity().await?;
                let results =
                    account.query_view(views, archive_filter).await?;
                out.push((identity, results));
            }
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
        match request.payload {
            IpcRequestBody::Status => {
                let paths = Paths::new_global(Paths::data_dir()?);
                let app = paths.has_app_lock()?;
                Ok(IpcResponse::Value(IpcResponseBody::Status {
                    app,
                    ipc: true,
                }))
            }
            IpcRequestBody::Ping => {
                Ok(IpcResponse::Value(IpcResponseBody::Pong))
            }
            IpcRequestBody::OpenUrl(_) => {
                // Open is a noop as we let the native bridge handle it
                Ok(IpcResponse::Value(IpcResponseBody::OpenUrl(false)))
            }
            IpcRequestBody::ListAccounts => {
                let data = self.list_accounts().await?;
                Ok(IpcResponse::Value(IpcResponseBody::Accounts(data)))
            }
            IpcRequestBody::Authenticate { address } => {
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
            IpcRequestBody::Lock { address } => {
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
            IpcRequestBody::Search { needle, filter } => {
                let data = self.search(needle, filter).await?;
                Ok(IpcResponse::Value(IpcResponseBody::Search(data)))
            }
            IpcRequestBody::QueryView {
                views,
                archive_filter,
            } => {
                let data = self
                    .query_view(views.as_slice(), archive_filter.as_ref())
                    .await?;
                Ok(IpcResponse::Value(IpcResponseBody::QueryView(data)))
            }
        }
    }
}
