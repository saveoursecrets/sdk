use crate::ServiceAppInfo;
use async_trait::async_trait;
use sos_net::sdk::account::{Account, AccountSwitcher};

use sos_protocol::{
    local_transport::{LocalRequest, LocalResponse},
    Merge, SyncStorage,
};
use std::sync::Arc;
use tokio::sync::RwLock;

// mod delegate;
mod local_server;

// pub use delegate::*;
use local_server::LocalServer;

/// Options for an IPC service.
#[derive(Default)]
pub struct IpcServiceOptions {
    /// Application info.
    pub app_info: Option<ServiceAppInfo>,
}

/// Handler for IPC requests.
pub struct IpcService {
    options: IpcServiceOptions,
    server: LocalServer,
}

impl IpcService {
    /// Create a new service handler.
    pub fn new<A, R, E>(
        accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
        options: IpcServiceOptions,
    ) -> Self
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
        let app_info = options.app_info.clone().unwrap_or_default();

        Self {
            server: LocalServer::new(app_info, accounts),
            options,
        }
    }

    /// Handle an incoming request.
    pub async fn handle(&self, request: LocalRequest) -> LocalResponse {
        self.server.handle(request).await
    }
}
