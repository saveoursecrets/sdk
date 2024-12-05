use crate::{
    codec, decode_proto, encode_proto, Error, Result, ServiceAppInfo,
};
use async_trait::async_trait;
use futures_util::sink::SinkExt;
use interprocess::local_socket::{tokio::prelude::*, GenericNamespaced};
use tokio_stream::StreamExt;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use sos_net::sdk::prelude::PublicIdentity;
use sos_protocol::{
    constants::routes::v1::ACCOUNTS_LIST,
    local_transport::{LocalRequest, LocalResponse},
    NetworkError,
};

/// Socket client for inter-process communication.
pub struct SocketClient {
    socket: Framed<LocalSocketStream, LengthDelimitedCodec>,
}

impl SocketClient {
    /// Create a client and connect the server.
    pub async fn connect(socket_name: &str) -> Result<Self> {
        let name = socket_name.to_ns_name::<GenericNamespaced>()?;
        let io = LocalSocketStream::connect(name).await?;
        Ok(Self {
            socket: codec::framed(io),
        })
    }

    /// Send a request.
    pub async fn send_request(
        &mut self,
        request: LocalRequest,
    ) -> Result<LocalResponse> {
        let request_id = request.request_id();
        let request: crate::WireLocalRequest = request.into();
        let buf = encode_proto(&request)?;
        self.socket.send(buf.into()).await?;
        let response = self.read_response().await?;

        // Response id will be zero if an error occurs
        // before a message_id could be parsed from the request
        if response.request_id() > 0 && request_id != response.request_id() {
            return Err(Error::MessageId(request_id, response.request_id()));
        }

        Ok(response)
    }

    /// Read response from the server.
    async fn read_response(&mut self) -> Result<LocalResponse> {
        let mut reply: Option<LocalResponse> = None;
        while let Some(message) = self.socket.next().await {
            match message {
                Ok(bytes) => {
                    let response: crate::WireLocalResponse =
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
}

/// Contract for types that expose an API to
/// app integrations such as browser extensions.
#[async_trait]
pub trait AppIntegration {
    /// App info.
    async fn info(&mut self) -> Result<ServiceAppInfo>;

    /// List the accounts on disc and include authentication state.
    async fn list_accounts(&mut self) -> Result<Vec<PublicIdentity>>;
}

#[async_trait]
impl AppIntegration for SocketClient {
    async fn info(&mut self) -> Result<ServiceAppInfo> {
        let response = self.send_request(Default::default()).await?;
        let status = response.status()?;
        if status.is_success() {
            let app_info: ServiceAppInfo =
                serde_json::from_slice(&response.body)?;
            Ok(app_info)
        } else {
            Err(NetworkError::ResponseCode(status).into())
        }
    }

    async fn list_accounts(&mut self) -> Result<Vec<PublicIdentity>> {
        let request = LocalRequest {
            uri: ACCOUNTS_LIST.parse()?,
            ..Default::default()
        };

        let response = self.send_request(request).await?;
        let status = response.status()?;
        if status.is_success() {
            let accounts: Vec<PublicIdentity> =
                serde_json::from_slice(&response.body)?;
            Ok(accounts)
        } else {
            Err(NetworkError::ResponseCode(status).into())
        }
    }
}
