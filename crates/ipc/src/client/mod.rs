use async_trait::async_trait;
use sos_net::sdk::account::AppIntegration;

use crate::{AccountsList, Error, IpcRequest, IpcResponse, Result};

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
                let request = IpcRequest::ListAccounts;
                if let IpcResponse::ListAccounts(list) =
                    self.send(request).await?
                {
                    Ok(list)
                } else {
                    Err(Error::ResponseType)
                }
            }
        }
    };
}

/// Shared functions for the TCP and local socket clients.
macro_rules! client_impl {
    () => {
        /// Send a request.
        pub(super) async fn send(
            &mut self,
            request: IpcRequest,
        ) -> Result<IpcResponse> {
            use std::sync::atomic::Ordering;
            let request_id = self.id.fetch_add(1, Ordering::SeqCst);
            let request: crate::WireIpcRequest = (request_id, request).into();
            let buf = encode_proto(&request)?;
            self.write_all(&buf).await?;
            let (response_id, response) = self.read_response().await?;

            if request_id != response_id {
                return Err(Error::MessageId(request_id, response_id));
            }

            Ok(response)
        }

        /// Read response from the server.
        async fn read_response(&mut self) -> Result<(u64, IpcResponse)> {
            let mut stream =
                FramedRead::new(&mut self.reader, BytesCodec::new());

            let mut reply: Option<(u64, IpcResponse)> = None;
            while let Some(message) = stream.next().await {
                match message {
                    Ok(bytes) => {
                        let response: crate::WireIpcResponse =
                            decode_proto(&bytes)?;
                        reply = Some(response.try_into()?);
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
