use async_trait::async_trait;
use std::time::{Duration, SystemTime};

use crate::{
    CommandOutcome, Error, IpcRequest, IpcRequestBody, IpcResponse,
    IpcResponseBody, Result, ServiceAppInfo,
};

use sos_net::sdk::prelude::{
    Address, ArchiveFilter, DocumentView, PublicIdentity, QueryFilter,
};

use sos_protocol::NetworkError;

// pub(crate) mod app_integration;

#[cfg(feature = "tcp")]
mod tcp;

#[cfg(feature = "local-socket")]
mod local_socket;

#[cfg(feature = "tcp")]
pub use tcp::*;

#[cfg(feature = "local-socket")]
pub use local_socket::*;

#[cfg(feature = "integration")]
use sos_protocol::{
    constants::routes::v1::ACCOUNTS_LIST,
    local_transport::{LocalRequest, LocalResponse},
};

/// Contract for types that expose an API to
/// app integrations such as browser extensions.
#[async_trait]
pub trait AppIntegration<E: From<sos_net::sdk::Error>> {
    /// App info.
    async fn info(&mut self) -> std::result::Result<ServiceAppInfo, E>;

    /*
    /// Ping the server.
    async fn ping(&mut self) -> std::result::Result<Duration, E>;
    */

    /// Send a request to the local server.
    #[cfg(feature = "integration")]
    async fn request(
        &mut self,
        request: LocalRequest,
    ) -> std::result::Result<LocalResponse, E>;

    /// List the accounts on disc and include authentication state.
    async fn list_accounts(
        &mut self,
    ) -> std::result::Result<Vec<PublicIdentity>, E>;
}

/// App integration functions for clients.
macro_rules! app_integration_impl {
    ($impl:ident) => {
        #[async_trait]
        impl AppIntegration<crate::Error> for $impl {
            async fn info(&mut self) -> Result<ServiceAppInfo> {
                let request = IpcRequest {
                    message_id: self.next_id(),
                    payload: IpcRequestBody::Http(Default::default()),
                };

                let response = self.send_request(request).await?;
                match response {
                    IpcResponse::Error {
                        message_id,
                        payload: err,
                    } => Err(Error::ResponseError(message_id, err)),
                    IpcResponse::Value {
                        payload: IpcResponseBody::Http(response),
                        ..
                    } => {
                        let status = response.status()?;
                        if status.is_success() {
                            let app_info: ServiceAppInfo =
                                serde_json::from_slice(&response.body)?;
                            Ok(app_info)
                        } else {
                            Err(NetworkError::ResponseCode(status).into())
                        }
                    }
                    _ => Err(Error::ResponseType),
                }
            }

            #[cfg(feature = "integration")]
            async fn request(
                &mut self,
                request: LocalRequest,
            ) -> Result<LocalResponse> {
                let request = IpcRequest {
                    message_id: self.next_id(),
                    payload: IpcRequestBody::Http(request),
                };
                let response = self.send_request(request).await?;
                match response {
                    IpcResponse::Error {
                        message_id,
                        payload: err,
                    } => Err(Error::ResponseError(message_id, err)),
                    IpcResponse::Value {
                        payload: IpcResponseBody::Http(response),
                        ..
                    } => Ok(response),
                    _ => Err(Error::ResponseType),
                }
            }

            async fn list_accounts(&mut self) -> Result<Vec<PublicIdentity>> {
                let request = IpcRequest {
                    message_id: self.next_id(),
                    payload: IpcRequestBody::Http(LocalRequest {
                        uri: ACCOUNTS_LIST.parse()?,
                        ..Default::default()
                    }),
                };

                let response = self.send_request(request).await?;
                match response {
                    IpcResponse::Error {
                        message_id,
                        payload: err,
                    } => Err(Error::ResponseError(message_id, err)),
                    IpcResponse::Value {
                        payload: IpcResponseBody::Http(response),
                        ..
                    } => {
                        let status = response.status()?;
                        if status.is_success() {
                            let accounts: Vec<PublicIdentity> =
                                serde_json::from_slice(&response.body)?;
                            Ok(accounts)
                        } else {
                            Err(NetworkError::ResponseCode(status).into())
                        }
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
