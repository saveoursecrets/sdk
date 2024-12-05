use crate::ServiceAppInfo;
use async_trait::async_trait;
use sos_account_extras::clipboard::NativeClipboard;
use sos_net::{
    sdk::account::{Account, AccountSwitcher, LocalAccount},
    NetworkAccount,
};

use sos_protocol::{
    local_transport::{LocalRequest, LocalResponse},
    Merge, SyncStorage,
};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::{mpsc, RwLock};

// mod delegate;
mod local_server;

// pub use delegate::*;
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
    /*
    /// Native clipboard.
    pub clipboard: Option<Arc<Mutex<NativeClipboard>>>,
    */
}

/// Service handler called by servers.
///
/// Some requests are delegated to a service delegate as they
/// may need to get input from the user and how that is done
/// will vary for each application.
#[async_trait]
pub trait IpcService<E> {
    /// Handle a request and reply with a response.
    async fn handle(&self, request: LocalRequest) -> LocalResponse;
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
    // delegate: mpsc::Sender<Command<A, R, E>>,
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
        // delegate: mpsc::Sender<Command<A, R, E>>,
        options: IpcServiceOptions,
    ) -> Self {
        let app_info = options.app_info.clone().unwrap_or_default();

        Self {
            server: LocalServer::new(app_info, accounts.clone()),
            accounts,
            // delegate,
            options,
        }
    }
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
    async fn handle(&self, request: LocalRequest) -> LocalResponse {
        self.server.handle(request).await
    }
}
