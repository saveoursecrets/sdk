use async_trait::async_trait;

use crate::{
    AccountsList, AppIntegration, AuthenticateOutcome, Error, IpcRequest,
    IpcResponse, IpcResponseBody, Result,
};

use sos_net::sdk::prelude::Address;

pub(crate) mod app_integration;

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
                let response = self.send(request).await?;
                match response {
                    IpcResponse::Error(err) => Err(Error::ResponseError(err)),
                    IpcResponse::Body(IpcResponseBody::ListAccounts(
                        list,
                    )) => Ok(list),
                    _ => Err(Error::ResponseType),
                }
            }

            async fn authenticate(
                &mut self,
                address: Address,
            ) -> Result<AuthenticateOutcome> {
                let request = IpcRequest::Authenticate { address };
                let response = self.send(request).await?;
                match response {
                    IpcResponse::Error(err) => Err(Error::ResponseError(err)),
                    IpcResponse::Body(IpcResponseBody::Authenticate(
                        outcome,
                    )) => Ok(outcome),
                    _ => Err(Error::ResponseType),
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

            // Response id will be zero if an error occurs
            // before a message_id could be parsed from the request
            if response_id > 0 && request_id != response_id {
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
