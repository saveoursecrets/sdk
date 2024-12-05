use crate::{
    io_err, ClipboardTarget, CommandOutcome, IpcRequest, IpcRequestBody,
    IpcResponse, IpcResponseBody, ServiceAppInfo,
};
use async_trait::async_trait;
use sos_account_extras::clipboard::NativeClipboard;
use sos_net::{
    protocol::{Merge, SyncStorage},
    sdk::{
        account::{Account, AccountSwitcher, LocalAccount},
        prelude::{ArchiveFilter, DocumentView, Identity, QueryFilter},
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
    LocalAccount,
    <LocalAccount as Account>::NetworkResult,
    <LocalAccount as Account>::Error,
>;

/// IPC service for network-enabled accounts.
pub type NetworkAccountIpcService = IpcServiceHandler<
    NetworkAccount,
    <NetworkAccount as Account>::NetworkResult,
    <NetworkAccount as Account>::Error,
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
pub struct IpcServiceHandler<A, R, E>
where
    A: Account<Error = E, NetworkResult = R>
        + SyncStorage
        + Merge
        + Sync
        + Send
        + 'static,
    R: 'static,
    E: std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
    delegate: mpsc::Sender<Command<A, R, E>>,
    options: IpcServiceOptions,
    server: LocalServer,
}

impl<A, R, E> IpcServiceHandler<A, R, E>
where
    A: Account<Error = E, NetworkResult = R>
        + SyncStorage
        + Merge
        + Sync
        + Send
        + 'static,
    R: 'static,
    E: std::error::Error
        + std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
{
    /// Create a new service handler.
    pub fn new(
        accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
        delegate: mpsc::Sender<Command<A, R, E>>,
        options: IpcServiceOptions,
    ) -> Self {
        let app_info = options.app_info.clone().unwrap_or_default();

        Self {
            server: LocalServer::new(app_info, accounts.clone()),
            accounts,
            delegate,
            options,
        }
    }

    /*
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
    */

    /*
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
    */
}

#[async_trait]
impl<A, R, E> IpcService<E> for IpcServiceHandler<A, R, E>
where
    A: Account<Error = E, NetworkResult = R>
        + SyncStorage
        + Merge
        + Sync
        + Send
        + 'static,
    R: 'static,
    E: std::error::Error
        + std::fmt::Debug
        + From<sos_net::sdk::Error>
        + From<std::io::Error>
        + 'static,
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
            IpcRequestBody::Http(req) => {
                let res = self.server.handle(req).await;
                Ok(IpcResponse::Value {
                    message_id,
                    payload: IpcResponseBody::Http(res),
                })
            }
        }
    }
}
