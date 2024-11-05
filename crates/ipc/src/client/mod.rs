use async_trait::async_trait;
use std::time::{Duration, SystemTime};

use crate::{
    AccountsList, AppIntegration, CommandOutcome, Error, IpcRequest,
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
            async fn ping(&mut self) -> Result<Duration> {
                let now = SystemTime::now();
                let request = IpcRequest::Ping;
                let response = self.send_request(request).await?;
                match response {
                    IpcResponse::Error(err) => Err(Error::ResponseError(err)),
                    IpcResponse::Value(IpcResponseBody::Pong) => {
                        Ok(now.elapsed()?)
                    }
                    _ => Err(Error::ResponseType),
                }
            }

            async fn list_accounts(&mut self) -> Result<AccountsList> {
                let request = IpcRequest::ListAccounts;
                let response = self.send_request(request).await?;
                match response {
                    IpcResponse::Error(err) => Err(Error::ResponseError(err)),
                    IpcResponse::Value(IpcResponseBody::Accounts(list)) => {
                        Ok(list)
                    }
                    _ => Err(Error::ResponseType),
                }
            }

            async fn authenticate(
                &mut self,
                address: Address,
            ) -> Result<CommandOutcome> {
                let request = IpcRequest::Authenticate { address };
                let response = self.send_request(request).await?;
                match response {
                    IpcResponse::Error(err) => Err(Error::ResponseError(err)),
                    IpcResponse::Value(IpcResponseBody::Authenticate(
                        outcome,
                    )) => Ok(outcome),
                    _ => Err(Error::ResponseType),
                }
            }

            async fn lock(
                &mut self,
                address: Address,
            ) -> Result<CommandOutcome> {
                let request = IpcRequest::Lock { address };
                let response = self.send_request(request).await?;
                match response {
                    IpcResponse::Error(err) => Err(Error::ResponseError(err)),
                    IpcResponse::Value(IpcResponseBody::Lock(outcome)) => {
                        Ok(outcome)
                    }
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
        pub async fn send_request(
            &mut self,
            request: IpcRequest,
        ) -> Result<IpcResponse> {
            use std::sync::atomic::Ordering;
            let request_id = self.id.fetch_add(1, Ordering::SeqCst);
            let request: crate::WireIpcRequest = (request_id, request).into();
            let buf = encode_proto(&request)?;
            self.socket.send(buf.into()).await?;
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
            let mut reply: Option<(u64, IpcResponse)> = None;
            while let Some(message) = self.socket.next().await {
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
    };
}

#[cfg(feature = "tcp")]
app_integration_impl!(TcpClient);

#[cfg(feature = "local-socket")]
app_integration_impl!(SocketClient);

pub(crate) use client_impl;
