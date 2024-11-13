use async_trait::async_trait;
use std::time::{Duration, SystemTime};

use crate::{
    AccountsList, AppIntegration, CommandOutcome, Error, IpcRequest,
    IpcRequestBody, IpcResponse, IpcResponseBody, Result, SearchResults,
    ServiceAppInfo,
};

use sos_net::sdk::prelude::{
    Address, ArchiveFilter, DocumentView, QueryFilter,
};

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
            async fn info(&mut self) -> Result<ServiceAppInfo> {
                let request = IpcRequest {
                    message_id: self.next_id(),
                    payload: IpcRequestBody::Info,
                };

                let response = self.send_request(request).await?;
                match response {
                    IpcResponse::Error {
                        message_id,
                        payload: err,
                    } => Err(Error::ResponseError(message_id, err)),
                    IpcResponse::Value {
                        payload: IpcResponseBody::Info(app),
                        ..
                    } => Ok(app),
                    _ => Err(Error::ResponseType),
                }
            }

            async fn ping(&mut self) -> Result<Duration> {
                let now = SystemTime::now();

                let request = IpcRequest {
                    message_id: self.next_id(),
                    payload: IpcRequestBody::Ping,
                };

                let response = self.send_request(request).await?;
                match response {
                    IpcResponse::Error {
                        message_id,
                        payload: err,
                    } => Err(Error::ResponseError(message_id, err)),
                    IpcResponse::Value {
                        payload: IpcResponseBody::Pong,
                        ..
                    } => Ok(now.elapsed()?),
                    _ => Err(Error::ResponseType),
                }
            }

            async fn list_accounts(&mut self) -> Result<AccountsList> {
                let request = IpcRequest {
                    message_id: self.next_id(),
                    payload: IpcRequestBody::ListAccounts,
                };
                let response = self.send_request(request).await?;
                match response {
                    IpcResponse::Error {
                        message_id,
                        payload: err,
                    } => Err(Error::ResponseError(message_id, err)),
                    IpcResponse::Value {
                        payload: IpcResponseBody::Accounts(list),
                        ..
                    } => Ok(list),
                    _ => Err(Error::ResponseType),
                }
            }

            async fn authenticate(
                &mut self,
                address: Address,
            ) -> Result<CommandOutcome> {
                let request = IpcRequest {
                    message_id: self.next_id(),
                    payload: IpcRequestBody::Authenticate { address },
                };
                let response = self.send_request(request).await?;
                match response {
                    IpcResponse::Error {
                        message_id,
                        payload: err,
                    } => Err(Error::ResponseError(message_id, err)),
                    IpcResponse::Value {
                        payload: IpcResponseBody::Authenticate(outcome),
                        ..
                    } => Ok(outcome),
                    _ => Err(Error::ResponseType),
                }
            }

            async fn lock(
                &mut self,
                address: Option<Address>,
            ) -> Result<CommandOutcome> {
                let request = IpcRequest {
                    message_id: self.next_id(),
                    payload: IpcRequestBody::Lock { address },
                };
                let response = self.send_request(request).await?;
                match response {
                    IpcResponse::Error {
                        message_id,
                        payload: err,
                    } => Err(Error::ResponseError(message_id, err)),
                    IpcResponse::Value {
                        payload: IpcResponseBody::Lock(outcome),
                        ..
                    } => Ok(outcome),
                    _ => Err(Error::ResponseType),
                }
            }

            async fn search(
                &mut self,
                needle: &str,
                filter: QueryFilter,
            ) -> Result<SearchResults> {
                let request = IpcRequest {
                    message_id: self.next_id(),
                    payload: IpcRequestBody::Search {
                        needle: needle.to_owned(),
                        filter,
                    },
                };
                let response = self.send_request(request).await?;
                match response {
                    IpcResponse::Error {
                        message_id,
                        payload: err,
                    } => Err(Error::ResponseError(message_id, err)),
                    IpcResponse::Value {
                        payload: IpcResponseBody::Search(results),
                        ..
                    } => Ok(results),
                    _ => Err(Error::ResponseType),
                }
            }

            async fn query_view(
                &mut self,
                views: Vec<DocumentView>,
                archive_filter: Option<ArchiveFilter>,
            ) -> Result<SearchResults> {
                let request = IpcRequest {
                    message_id: self.next_id(),
                    payload: IpcRequestBody::QueryView {
                        views,
                        archive_filter,
                    },
                };
                let response = self.send_request(request).await?;
                match response {
                    IpcResponse::Error {
                        message_id,
                        payload: err,
                    } => Err(Error::ResponseError(message_id, err)),
                    IpcResponse::Value {
                        payload: IpcResponseBody::QueryView(results),
                        ..
                    } => Ok(results),
                    _ => Err(Error::ResponseType),
                }
            }
        }
    };
}

/// Shared functions for the TCP and local socket clients.
macro_rules! client_impl {
    () => {
        pub(super) fn next_id(&self) -> u32 {
            use std::sync::atomic::Ordering;
            self.id.fetch_add(1, Ordering::SeqCst)
        }

        /// Send a request.
        pub async fn send_request(
            &mut self,
            request: IpcRequest,
        ) -> Result<IpcResponse> {
            let request_id = request.message_id;
            let request: crate::WireIpcRequest = request.into();
            let buf = encode_proto(&request)?;
            self.socket.send(buf.into()).await?;
            let response = self.read_response().await?;

            // Response id will be zero if an error occurs
            // before a message_id could be parsed from the request
            if response.message_id() > 0
                && request_id != response.message_id()
            {
                return Err(Error::MessageId(
                    request_id,
                    response.message_id(),
                ));
            }

            Ok(response)
        }

        /// Read response from the server.
        async fn read_response(&mut self) -> Result<IpcResponse> {
            let mut reply: Option<IpcResponse> = None;
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
