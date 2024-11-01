use sos_net::sdk::prelude::{Account, LocalAccount};
use sos_net::NetworkAccount;
use std::sync::Arc;
use tokio::net::{TcpListener, ToSocketAddrs};
use tokio::sync::RwLock;

use crate::{
    IpcService, LocalAccountIpcService, NetworkAccountIpcService, Result,
};

/// TCP server for network-enabled accounts.
pub type NetworkAccountTcpServer =
    TcpServer<NetworkAccountIpcService, <NetworkAccount as Account>::Error>;

/// TCP server for local accounts.
pub type LocalAccountTcpServer =
    TcpServer<LocalAccountIpcService, <LocalAccount as Account>::Error>;

/// TCP server for inter-process communication.
pub struct TcpServer<S, E>
where
    S: IpcService<E> + Send + Sync + 'static,
    E: Send,
{
    phantom: std::marker::PhantomData<(S, E)>,
}

impl<S, E> TcpServer<S, E>
where
    S: IpcService<E> + Send + Sync + 'static,
    E: Send + From<std::io::Error> + std::fmt::Debug,
{
    /// Listen on a bind address.
    pub async fn listen<A: ToSocketAddrs>(
        addr: A,
        service: Arc<RwLock<S>>,
    ) -> Result<()> {
        let listener = TcpListener::bind(&addr).await?;
        loop {
            let (socket, _) = listener.accept().await?;
            let service = service.clone();
            tokio::spawn(async move {
                super::handle_conn(service, socket).await;
            });
        }
    }
}
