//! Send HTTP requests to a named pipe.

use crate::{Result, ServiceAppInfo};
use bytes::Bytes;
use http::{header::CONNECTION, Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1::handshake;
use interprocess::local_socket::{tokio::prelude::*, GenericNamespaced};
use std::pin::Pin;
use tokio::io::DuplexStream;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::local_transport::{LocalRequest, LocalResponse};
use hyper_util::rt::tokio::TokioIo;
use sos_protocol::{constants::routes::v1::ACCOUNTS_LIST, NetworkError};
use sos_sdk::prelude::PublicIdentity;

/// Socket client for inter-process communication.
pub struct LocalSocketClient {
    socket_name: String,
}

impl LocalSocketClient {
    /// Create a client and connect to the named pipe.
    pub async fn connect(socket_name: impl Into<String>) -> Result<Self> {
        Ok(Self {
            socket_name: socket_name.into(),
        })
    }

    /// Send on a local duplex stream.
    pub async fn send_local(
        stream: DuplexStream,
        request: LocalRequest,
    ) -> Result<LocalResponse> {
        todo!();
    }

    /// Send a local request.
    pub async fn send_request(
        &mut self,
        request: LocalRequest,
    ) -> Result<LocalResponse> {
        let name =
            self.socket_name.clone().to_ns_name::<GenericNamespaced>()?;
        let io = LocalSocketStream::connect(name).await?;

        let request: Request<Vec<u8>> = request.try_into()?;
        let (mut header, body) = request.into_parts();
        header.headers.insert(CONNECTION, "close".parse().unwrap());
        let request =
            Request::from_parts(header, Full::new(Bytes::from(body)));

        let response = self.send_http(Box::pin(io), request).await?;
        let (header, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        let response = Response::from_parts(header, bytes.to_vec());
        Ok(response.into())
    }

    /// Send a HTTP request.
    async fn send_http<I>(
        &mut self,
        io: Pin<Box<I>>,
        request: Request<Full<Bytes>>,
    ) -> Result<Response<Full<Bytes>>>
    where
        I: AsyncRead + AsyncWrite + Send + Sync + 'static,
    {
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
        let response = Response::from_parts(header, Full::new(bytes));
        Ok(response)
    }

    /*
    /// Send a HTTP request.
    async fn send_http2<T>(
        &mut self,
        socket: TokioIo<T>,
        request: Request<Full<Bytes>>,
    ) -> Result<Response<Full<Bytes>>>
    where
        T: Unpin + AsyncRead + AsyncWrite + Send + Sync + 'static,
    {
        let (mut sender, conn) = handshake(socket).await?;

        tokio::task::spawn(async move {
            if let Err(err) = conn.await {
                tracing::error!(error = %err, "ipc::client::connection");
            }
        });

        let response = sender.send_request(request).await?;
        let (header, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        let response = Response::from_parts(header, Full::new(bytes));
        Ok(response)
    }
    */

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
