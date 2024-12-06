use crate::{io::TokioAdapter, LocalServer, Result, ServiceAppInfo};
use hyper::server::conn::http1::Builder;
use interprocess::local_socket::{
    tokio::prelude::*, GenericNamespaced, ListenerOptions,
};
use sos_protocol::{Merge, SyncStorage};
use sos_sdk::prelude::{Account, AccountSwitcher};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Options for an IPC service.
#[derive(Default, Clone)]
pub struct ServiceOptions {
    /// Application info.
    pub app_info: Option<ServiceAppInfo>,
}

/// Socket server for inter-process communication.
pub struct SocketServer;

impl SocketServer {
    /// Listen on a bind address.
    pub async fn listen<A, R, E>(
        socket_name: &str,
        accounts: Arc<RwLock<AccountSwitcher<A, R, E>>>,
        options: ServiceOptions,
    ) -> Result<()>
    where
        A: Account<Error = E, NetworkResult = R>
            + SyncStorage
            + Merge
            + Sync
            + Send
            + 'static,
        R: 'static,
        E: std::fmt::Debug
            + From<sos_sdk::Error>
            + From<std::io::Error>
            + 'static,
    {
        let name = socket_name.to_ns_name::<GenericNamespaced>()?;
        let opts = ListenerOptions::new().name(name);
        let listener = match opts.create_tokio() {
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                tracing::error!(
                    "Error: could not start server because the socket file is occupied. Please check if {socket_name} is in use by another process and try again."
                );
                return Err(e.into());
            }
            x => x?,
        };

        let service =
            LocalServer::new(options.app_info.unwrap_or_default(), accounts);
        let svc = Arc::new(service);

        loop {
            let socket = listener.accept().await?;
            let svc = svc.clone();
            tokio::spawn(async move {
                let socket = TokioAdapter::new(socket);
                let http = Builder::new();
                let conn = http.serve_connection(socket, svc);
                if let Err(e) = conn.await {
                    tracing::error!(error = %e);
                }
            });
        }
    }
}
