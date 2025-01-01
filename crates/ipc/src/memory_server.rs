//! HTTP server that listens for connections
//! using in-memory duplex streams.
use crate::{
    local_transport::{LocalRequest, LocalResponse},
    LocalWebService, Result, ServiceAppInfo, WebAccounts,
};
use bytes::Bytes;
use http::{header::CONNECTION, Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1::handshake;
use hyper::server::conn::http1::Builder;
use hyper_util::rt::tokio::TokioIo;
use sos_account::Account;
use sos_sdk::prelude::ErrorExt;
use sos_sync::SyncStorage;
use std::sync::Arc;
use tokio::{
    io::DuplexStream,
    sync::{mpsc, oneshot},
};

/// Client for the in-memory HTTP server.
#[derive(Clone)]
pub struct LocalMemoryClient {
    connect_tx: mpsc::Sender<oneshot::Sender<DuplexStream>>,
}

impl LocalMemoryClient {
    /// Send a request.
    pub async fn send(&self, request: LocalRequest) -> Result<LocalResponse> {
        let stream = self.connect().await?;

        let request: Request<Vec<u8>> = request.try_into()?;
        let (mut header, body) = request.into_parts();
        header.headers.insert(CONNECTION, "close".parse().unwrap());
        let request =
            Request::from_parts(header, Full::new(Bytes::from(body)));

        let response = self.send_http(stream, request).await?;
        let (header, body) = response.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        let response = Response::from_parts(header, bytes.to_vec());
        Ok(response.into())
    }

    /// Connect to the server.
    async fn connect(&self) -> Result<DuplexStream> {
        let (tx, rx) = oneshot::channel::<DuplexStream>();
        self.connect_tx.send(tx).await.unwrap();
        Ok(rx.await.unwrap())
    }

    /// Send a HTTP request.
    async fn send_http(
        &self,
        io: DuplexStream,
        request: Request<Full<Bytes>>,
    ) -> Result<Response<Full<Bytes>>> {
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
        let request = LocalRequest::get("/accounts".parse()?);
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
    */
}

/// Server for in-memory communication.
pub struct LocalMemoryServer;

impl LocalMemoryServer {
    /// Listen to an in-memory stream.
    pub async fn listen<A, R, E>(
        accounts: WebAccounts<A, R, E>,
        app_info: ServiceAppInfo,
    ) -> Result<LocalMemoryClient>
    where
        A: Account<Error = E, NetworkResult = R>
            + SyncStorage
            + Sync
            + Send
            + 'static,
        R: 'static,
        E: std::fmt::Debug
            + std::error::Error
            + ErrorExt
            + From<sos_sdk::Error>
            + From<sos_database::Error>
            + From<sos_account::Error>
            + From<std::io::Error>
            + Send
            + Sync
            + 'static,
    {
        let service = LocalWebService::new(app_info, accounts);
        let svc = Arc::new(service);

        let (conn_tx, mut conn_rx) =
            mpsc::channel::<oneshot::Sender<DuplexStream>>(64);
        let client = LocalMemoryClient {
            connect_tx: conn_tx,
        };
        tokio::task::spawn(async move {
            while let Some(notify) = conn_rx.recv().await {
                let (client, server) = tokio::io::duplex(4096);

                notify.send(client).unwrap();

                let socket = TokioIo::new(server);
                let mut http = Builder::new();
                http.auto_date_header(false);

                tracing::debug!("memory_server::new_connection");
                let conn = http.serve_connection(socket, svc.clone());
                if let Err(err) = conn.await {
                    tracing::error!(
                      error = %err,
                      "memory_server::connection_error");
                }
                tracing::debug!("memory_server::connection_close");
            }
        });

        Ok(client)
    }
}
