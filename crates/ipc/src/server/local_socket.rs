use interprocess::local_socket::{
    tokio::prelude::*, GenericNamespaced, ListenerOptions,
};
use sos_net::{
    sdk::prelude::{Account, LocalAccount},
    NetworkAccount,
};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{
    IpcService, LocalAccountIpcService, NetworkAccountIpcService, Result,
};

/// Socket server for network-enabled accounts.
pub type NetworkAccountSocketServer = SocketServer<
    NetworkAccountIpcService,
    <NetworkAccount as Account>::Error,
>;

/// Socket server for local accounts.
pub type LocalAccountSocketServer =
    SocketServer<LocalAccountIpcService, <LocalAccount as Account>::Error>;

/// Socket server for inter-process communication.
pub struct SocketServer<S, E>
where
    S: IpcService<E> + Send + Sync + 'static,
    E: Send,
{
    phantom: std::marker::PhantomData<(S, E)>,
}

impl<S, E> SocketServer<S, E>
where
    S: IpcService<E> + Send + Sync + 'static,
    E: Send + From<std::io::Error> + std::fmt::Debug + std::fmt::Display,
{
    /// Listen on a bind address.
    pub async fn listen(
        socket_name: &str,
        service: Arc<RwLock<S>>,
    ) -> Result<()> {
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

        loop {
            let socket = listener.accept().await?;
            let service = service.clone();
            tokio::spawn(async move {
                super::handle_conn(service, socket).await;
            });
        }
    }
}
