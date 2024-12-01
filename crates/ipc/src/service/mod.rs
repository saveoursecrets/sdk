use crate::{
    io_err, AccountsList, ClipboardTarget, CommandOutcome, IpcRequest,
    IpcRequestBody, IpcResponse, IpcResponseBody, SearchResults,
    ServiceAppInfo,
};
use async_trait::async_trait;
use sos_account_extras::clipboard::NativeClipboard;
use sos_net::{
    sdk::{
        account::{Account, AccountSwitcher, LocalAccount},
        encode,
        prelude::{
            ArchiveFilter, DocumentView, Identity, QualifiedPath, QueryFilter,
        },
        Paths,
    },
    NetworkAccount,
};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::{mpsc, RwLock};

mod delegate;
mod local_server;

pub use delegate::*;
use local_server::LocalServer;

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

/// Options for an IPC service.
#[derive(Default)]
pub struct IpcServiceOptions {
    /// Application info.
    pub app_info: Option<ServiceAppInfo>,
    /// Native clipboard.
    pub clipboard: Option<Arc<Mutex<NativeClipboard>>>,
}

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
    options: IpcServiceOptions,
    server: LocalServer<E, R, A>,
}

impl<E, R, A> IpcServiceHandler<E, R, A>
where
    E: std::error::Error
        + std::fmt::Debug
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
        options: IpcServiceOptions,
    ) -> Self {
        Self {
            server: LocalServer::new(accounts.clone()),
            accounts,
            delegate,
            options,
        }
    }

    async fn list_accounts(&self) -> std::result::Result<AccountsList, E> {
        let accounts = self.accounts.read().await;
        let mut out = Vec::new();
        let disc_accounts =
            Identity::list_accounts(accounts.data_dir()).await?;
        for account in disc_accounts {
            let (authenticated, folders) = if let Some(memory_account) =
                accounts.iter().find(|a| a.address() == account.address())
            {
                let authenticated = memory_account.is_authenticated().await;

                if authenticated {
                    (authenticated, memory_account.list_folders().await?)
                } else {
                    (authenticated, Vec::new())
                }
            } else {
                (false, Vec::new())
            };

            out.push((
                account,
                authenticated,
                folders.iter().map(|f| f.into()).collect(),
            ));
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

    /// Copy to the clipboard.
    async fn copy_clipboard(
        &self,
        target: ClipboardTarget,
    ) -> Result<CommandOutcome, E> {
        if self.options.clipboard.is_none() {
            return Ok(CommandOutcome::Unsupported);
        }

        let accounts = self.accounts.read().await;
        let account = accounts
            .iter()
            .find(|a| a.address() == target.path.address());
        Ok(if let Some(account) = account {
            if account.is_authenticated().await {
                let target_folder =
                    account.find(|f| f.id() == target.path.folder_id()).await;
                if let Some(folder) = target_folder {
                    let current_folder = account.current_folder().await?;
                    let (data, _) = account
                        .read_secret(target.path.secret_id(), Some(folder))
                        .await?;
                    if let Some(current) = &current_folder {
                        account.open_folder(current).await?;
                    }
                    let secret = data.secret();

                    let clipboard = self.options.clipboard.as_ref().unwrap();
                    let clipboard = clipboard.lock().await;
                    match clipboard.copy_secret_value(secret).await {
                        Ok(_) => CommandOutcome::Success,
                        Err(e) => {
                            tracing::error!(
                                error = %e, "clipboard::copy_secret");
                            CommandOutcome::Failed
                        }
                    }
                } else {
                    CommandOutcome::NotFound
                }
            } else {
                CommandOutcome::NotAuthenticated
            }
        } else {
            CommandOutcome::NotFound
        })
    }

    /// Read secret.
    async fn read_secret(
        &self,
        target: QualifiedPath,
    ) -> Result<(CommandOutcome, Option<Vec<u8>>), E> {
        let accounts = self.accounts.read().await;
        let account =
            accounts.iter().find(|a| a.address() == target.address());
        Ok(if let Some(account) = account {
            if account.is_authenticated().await {
                let target_folder =
                    account.find(|f| f.id() == target.folder_id()).await;
                if let Some(folder) = target_folder {
                    let (vault_commit, _) = account
                        .raw_secret(folder.id(), target.secret_id())
                        .await?;
                    let result = if let Some(commit) = vault_commit {
                        let buffer = encode(&commit).await?;
                        Some(buffer)
                    } else {
                        None
                    };

                    (CommandOutcome::Success, result)
                } else {
                    (CommandOutcome::NotFound, None)
                }
            } else {
                (CommandOutcome::NotAuthenticated, None)
            }
        } else {
            (CommandOutcome::NotFound, None)
        })
    }
}

#[async_trait]
impl<E, R, A> IpcService<E> for IpcServiceHandler<E, R, A>
where
    E: std::error::Error
        + std::fmt::Debug
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
        let message_id = request.message_id;
        match request.payload {
            IpcRequestBody::Probe => Ok(IpcResponse::Value {
                message_id,
                payload: IpcResponseBody::Probe,
            }),
            IpcRequestBody::Info => {
                let app_info =
                    self.options.app_info.clone().unwrap_or_default();
                Ok(IpcResponse::Value {
                    message_id,
                    payload: IpcResponseBody::Info(app_info),
                })
            }
            IpcRequestBody::Status => {
                let paths = Paths::new_global(Paths::data_dir()?);
                let app = paths.has_app_lock()?;
                Ok(IpcResponse::Value {
                    message_id,
                    payload: IpcResponseBody::Status(app),
                })
            }
            IpcRequestBody::Ping => Ok(IpcResponse::Value {
                message_id,
                payload: IpcResponseBody::Pong,
            }),
            IpcRequestBody::OpenUrl(_) => {
                // Open is a noop as we let the native bridge handle it
                Ok(IpcResponse::Value {
                    message_id,
                    payload: IpcResponseBody::OpenUrl(false),
                })
            }
            IpcRequestBody::ListAccounts => {
                let data = self.list_accounts().await?;
                Ok(IpcResponse::Value {
                    message_id,
                    payload: IpcResponseBody::Accounts(data),
                })
            }
            IpcRequestBody::Copy(target) => {
                let outcome = self.copy_clipboard(target).await?;
                Ok(IpcResponse::Value {
                    message_id,
                    payload: IpcResponseBody::Copy(outcome),
                })
            }
            IpcRequestBody::Authenticate { address } => {
                let (result, result_rx) = tokio::sync::oneshot::channel();
                let command = Command {
                    accounts: self.accounts.clone(),
                    options: CommandOptions::Authenticate { address, result },
                };
                match self.delegate.send(command).await {
                    Ok(_) => match result_rx.await {
                        Ok(outcome) => Ok(IpcResponse::Value {
                            message_id,
                            payload: IpcResponseBody::Authenticate(outcome),
                        }),
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
                        Ok(outcome) => Ok(IpcResponse::Value {
                            message_id,
                            payload: IpcResponseBody::Lock(outcome),
                        }),
                        Err(err) => Err(io_err(err).into()),
                    },
                    Err(err) => Err(io_err(err).into()),
                }
            }
            IpcRequestBody::Search { needle, filter } => {
                let data = self.search(needle, filter).await?;
                Ok(IpcResponse::Value {
                    message_id,
                    payload: IpcResponseBody::Search(data),
                })
            }
            IpcRequestBody::QueryView {
                views,
                archive_filter,
            } => {
                let data = self
                    .query_view(views.as_slice(), archive_filter.as_ref())
                    .await?;
                Ok(IpcResponse::Value {
                    message_id,
                    payload: IpcResponseBody::QueryView(data),
                })
            }

            IpcRequestBody::ReadSecret { path } => {
                let (outcome, data) = self.read_secret(path).await?;

                todo!("handle read secret outline request");

                /*
                Ok(IpcResponse::Value {
                    message_id,
                    payload: IpcResponseBody::ReadSecretOutline((outcome, data)),
                })
                */
            }
        }
    }
}
