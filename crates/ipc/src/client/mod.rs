use async_trait::async_trait;
use sos_net::sdk::account::AppIntegration;
use std::sync::atomic::Ordering;

use crate::{AccountsList, AccountsListRequest, Result, WireIpcRequest};

#[cfg(feature = "tcp")]
mod tcp;

#[cfg(feature = "local-socket")]
mod local_socket;

#[cfg(feature = "tcp")]
pub use tcp::*;

#[cfg(feature = "local-socket")]
pub use local_socket::*;

/// App integration functions for clients.
macro_rules! app_integration_impl {
    ($impl:ident) => {
        #[async_trait]
        impl AppIntegration<crate::Error> for $impl {
            async fn list_accounts(&mut self) -> Result<AccountsList> {
                let message_id = self.id.fetch_add(1, Ordering::SeqCst);
                let req = AccountsListRequest;
                let request: WireIpcRequest = (message_id, req).into();
                let response = self.send(request).await?;
                Ok(response.try_into()?)
            }
        }
    };
}

/// Shared functions for the TCP and local socket clients.
macro_rules! client_impl {
    () => {
        /// Send a request.
        pub(super) async fn send<R: prost::Message>(
            &mut self,
            request: R,
        ) -> Result<WireIpcResponse> {
            let buf = encode_proto(&request)?;
            self.write_all(&buf).await?;
            self.read_response().await
        }

        /// Read response from the server.
        async fn read_response(&mut self) -> Result<WireIpcResponse> {
            let mut stream =
                FramedRead::new(&mut self.reader, BytesCodec::new());

            let mut reply: Option<WireIpcResponse> = None;
            while let Some(message) = stream.next().await {
                match message {
                    Ok(bytes) => {
                        let response: WireIpcResponse = decode_proto(&bytes)?;
                        reply = Some(response);
                        break;
                    }
                    Err(err) => {
                        return Err(err.into());
                    }
                }
            }
            reply.ok_or(Error::NoResponse)
        }

        /// Write a buffer.
        async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
            self.writer.write_all(buf).await?;
            Ok(self.writer.flush().await?)
        }
    };
}

#[cfg(feature = "tcp")]
app_integration_impl!(TcpClient);

#[cfg(feature = "local-socket")]
app_integration_impl!(SocketClient);

pub(crate) use client_impl;
