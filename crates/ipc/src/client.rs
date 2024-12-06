use crate::{Result, ServiceAppInfo};
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1::handshake;
use interprocess::local_socket::{tokio::prelude::*, GenericNamespaced};

use hyper_util::rt::tokio::TokioIo;
use sos_protocol::{
    constants::routes::v1::ACCOUNTS_LIST,
    local_transport::{LocalRequest, LocalResponse},
    NetworkError,
};
use sos_sdk::prelude::PublicIdentity;

/// Send a local request.
pub async fn send_local(
    socket_name: impl Into<String>,
    request: LocalRequest,
) -> Result<LocalResponse> {
    let request: Request<Vec<u8>> = request.try_into()?;
    let (header, body) = request.into_parts();
    let request = Request::from_parts(header, Full::new(Bytes::from(body)));
    let response = send_http(socket_name, request).await?;
    let (header, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    let response = Response::from_parts(header, bytes.to_vec());
    Ok(response.into())
}

/// Send a HTTP request.
pub async fn send_http(
    socket_name: impl Into<String>,
    request: Request<Full<Bytes>>,
) -> Result<Response<Full<Bytes>>> {
    let name = socket_name.into().to_ns_name::<GenericNamespaced>()?;
    let io = LocalSocketStream::connect(name).await?;
    let socket = TokioIo::new(io);
    let (mut sender, conn) = handshake(socket).await?;
    tokio::task::spawn(async move {
        if let Err(err) = conn.await {
            tracing::error!(error = %err, "ipc::client::connection");
        }
    });
    let response = sender.send_request(request).await?;
    let (header, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    Ok(Response::from_parts(header, Full::new(bytes)))
}

/// Socket client for inter-process communication.
pub struct LocalSocketClient {
    socket_name: String,
}

impl LocalSocketClient {
    /// Create a client and connect the server.
    pub async fn connect(socket_name: impl Into<String>) -> Result<Self> {
        Ok(Self {
            socket_name: socket_name.into(),
        })
    }

    /// Send a local request.
    pub async fn send_request(
        &self,
        request: LocalRequest,
    ) -> Result<LocalResponse> {
        send_local(self.socket_name.clone(), request).await
    }

    /// Get application information.
    pub async fn info(&self) -> Result<ServiceAppInfo> {
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

    /// List accounts.
    pub async fn list_accounts(&self) -> Result<Vec<PublicIdentity>> {
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
