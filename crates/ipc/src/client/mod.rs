use async_trait::async_trait;
use sos_net::sdk::account::AppIntegration;
use std::sync::atomic::Ordering;

use crate::{AccountsList, AccountsListRequest, IpcRequest, Result};

#[cfg(feature = "tcp")]
mod tcp;

#[cfg(feature = "local-socket")]
mod local_socket;

#[cfg(feature = "tcp")]
pub use tcp::*;

#[cfg(feature = "local-socket")]
pub use local_socket::*;

macro_rules! app_integration_impl {
    ($impl:ident) => {
        #[async_trait]
        impl AppIntegration<crate::Error> for $impl {
            async fn list_accounts(&mut self) -> Result<AccountsList> {
                let message_id = self.id.fetch_add(1, Ordering::SeqCst);
                let req = AccountsListRequest;
                let request: IpcRequest = (message_id, req).into();
                let response = self.send(request).await?;
                Ok(response.try_into()?)
            }
        }
    };
}

#[cfg(feature = "tcp")]
app_integration_impl!(TcpClient);

#[cfg(feature = "local-socket")]
app_integration_impl!(SocketClient);
