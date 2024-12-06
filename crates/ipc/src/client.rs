//! Send HTTP requests to a named pipe.

use crate::{Result, ServiceAppInfo};
use bytes::Bytes;
use futures::pin_mut;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1::handshake;
use interprocess::local_socket::{tokio::prelude::*, GenericNamespaced};

use crate::local_transport::{LocalRequest, LocalResponse};
use hyper_util::rt::tokio::TokioIo;
use sos_protocol::{constants::routes::v1::ACCOUNTS_LIST, NetworkError};
use sos_sdk::prelude::PublicIdentity;

/// Socket client for inter-process communication.
pub struct LocalSocketClient {
    socket: TokioIo<LocalSocketStream>,
}

impl LocalSocketClient {
    /// Create a client and connect to the named pipe.
    pub async fn connect(socket_name: impl Into<String>) -> Result<Self> {
        let name = socket_name.into().to_ns_name::<GenericNamespaced>()?;
        let io = LocalSocketStream::connect(name).await?;
        let socket = TokioIo::new(io);
        Ok(Self { socket })
    }

    /// Send a local request.
    pub async fn send_request(
        &mut self,
        request: LocalRequest,
    ) -> Result<LocalResponse> {
        let request: Request<Vec<u8>> = request.try_into()?;
        let (header, body) = request.into_parts();
        let request =
            Request::from_parts(header, Full::new(Bytes::from(body)));
        let response = self.send_http(request).await?;
        let (header, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        let response = Response::from_parts(header, bytes.to_vec());
        Ok(response.into())
    }

    /// Send a HTTP request.
    pub async fn send_http(
        &mut self,
        request: Request<Full<Bytes>>,
    ) -> Result<Response<Full<Bytes>>> {
        let (mut sender, conn) = handshake(&mut self.socket).await?;

        let conn = Box::pin(async move { conn.await });
        let req = Box::pin(async move { sender.send_request(request).await });
        pin_mut!(conn);
        pin_mut!(req);

        let (conn, response) = futures::future::join(conn, req).await;
        if let Err(err) = conn {
            tracing::error!(error = %err, "ipc::client::connection");
        }

        let (header, body) = response?.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        let response = Response::from_parts(header, Full::new(bytes));

        Ok(response)
    }

    /// Get application information.
    pub async fn info(&mut self) -> Result<ServiceAppInfo> {
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
    pub async fn list_accounts(&mut self) -> Result<Vec<PublicIdentity>> {
        let request = LocalRequest::get(ACCOUNTS_LIST.parse()?);

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
