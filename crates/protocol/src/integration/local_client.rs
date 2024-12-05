//! Local client implements the sync protocol for linked
//! accounts.
//!
//! It sends requests over a local, unauthenticated,
//! insecure communication channel such as a named pipe.
//!
//! Th client is transport-agnostic to support different
//! communcation channels for different app integrations.
//! For example, the browser extensions would communicate
//! using the native messaging API which is proxied
//! over the IPC channel using names pipes.
//!
//! Communication is performed the same way as the network-aware
//! client sending only encrypted data in the payloads.
//!
//! However, unlike network-based syncing no authorization header
//! is included as there is an inherent trust established when
//! the app integration was installed on the device.

use crate::{
    error::NetworkError,
    local_transport::{LocalResponse, LocalTransport},
    CreateSet, DiffRequest, DiffResponse, Error, Origin, PatchRequest,
    PatchResponse, Result, ScanRequest, ScanResponse, SyncClient, SyncPacket,
    SyncStatus, UpdateSet, WireEncodeDecode,
};
use async_trait::async_trait;
use http::{header::CONTENT_TYPE, Method, Request, StatusCode, Uri};
use serde_json::Value;
use sos_sdk::{
    constants::{
        routes::v1::{
            SYNC_ACCOUNT, SYNC_ACCOUNT_EVENTS, SYNC_ACCOUNT_STATUS,
        },
        MIME_TYPE_PROTOBUF, X_SOS_ACCOUNT_ID,
    },
    prelude::Address,
};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::instrument;

use bytes::Bytes;
use std::io::Read;
use xz::read::XzDecoder;

type ClientTransport = Box<dyn LocalTransport + Send + Sync + 'static>;

/// Local client.
#[derive(Clone)]
pub struct LocalClient {
    origin: Origin,
    transport: Arc<Mutex<ClientTransport>>,
}

impl LocalClient {
    /// Create a local client.
    pub fn new(
        origin: Origin,
        transport: Arc<Mutex<ClientTransport>>,
    ) -> Self {
        Self { origin, transport }
    }

    /// Build a URI for the local client.
    fn build_uri(&self, route: &str) -> Result<Uri> {
        Ok(Uri::builder()
            .scheme(self.origin.url().scheme())
            .authority(self.origin.url().authority())
            .path_and_query(route)
            .build()?)
    }

    /// Check if we are able to handle a response status code
    /// and content type.
    async fn check_response(
        &self,
        response: LocalResponse,
    ) -> Result<LocalResponse> {
        let status = response.status()?;
        let content_type = response.content_type();
        match (status, content_type) {
            // OK with the correct MIME type can be handled
            (http::StatusCode::OK, Some(content_type)) => {
                if content_type == MIME_TYPE_PROTOBUF {
                    Ok(response)
                } else {
                    Err(NetworkError::ContentType(
                        content_type.to_owned(),
                        MIME_TYPE_PROTOBUF.to_string(),
                    )
                    .into())
                }
            }
            // Otherwise exit out early
            _ => self.error_json(response).await,
        }
    }

    /// Convert an error response that may be JSON
    /// into an error.
    async fn error_json(
        &self,
        response: LocalResponse,
    ) -> Result<LocalResponse> {
        let status = response.status()?;
        if !status.is_success() {
            if response.is_json() {
                let value: Value = serde_json::from_slice(&response.body)?;
                Err(NetworkError::ResponseJson(status, value).into())
            } else {
                Err(NetworkError::ResponseCode(status).into())
            }
        } else {
            Ok(response)
        }
    }

    fn read_response_body(&self, response: LocalResponse) -> Result<Bytes> {
        if response.is_xz() {
            let mut buffer = Vec::new();
            let mut decompressor = XzDecoder::new(response.body.as_slice());
            decompressor.read_to_end(&mut buffer)?;
            Ok(buffer.into())
        } else {
            Ok(response.body.into())
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl SyncClient for LocalClient {
    type Error = Error;

    fn origin(&self) -> &Origin {
        &self.origin
    }

    #[instrument(skip(self))]
    async fn account_exists(&self, address: &Address) -> Result<bool> {
        let uri = self.build_uri(SYNC_ACCOUNT)?;
        tracing::debug!(uri = %uri, "local_client::account_exists");

        let request = Request::builder()
            .method(Method::HEAD)
            .uri(uri)
            .header(X_SOS_ACCOUNT_ID, address.to_string())
            .body(Default::default())?;

        let response = {
            let mut transport = self.transport.lock().await;
            transport.call(request.into()).await?
        };

        let status = response.status()?;
        tracing::debug!(status = %status, "local_client::account_exists");
        let exists = match status {
            StatusCode::OK => true,
            StatusCode::NOT_FOUND => false,
            _ => {
                return Err(NetworkError::ResponseCode(status).into());
            }
        };

        Ok(exists)
    }

    async fn create_account(
        &self,
        address: &Address,
        account: CreateSet,
    ) -> Result<()> {
        let body = account.encode().await?;
        let uri = self.build_uri(SYNC_ACCOUNT)?;
        tracing::debug!(uri = %uri, "local_client::create_account");

        let request = Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .header(X_SOS_ACCOUNT_ID, address.to_string())
            .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF)
            .body(body)?;

        let response = {
            let mut transport = self.transport.lock().await;
            transport.call(request.into()).await?
        };

        let status = response.status()?;
        tracing::debug!(status = %status, "local_client::create_account");
        self.error_json(response).await?;
        Ok(())
    }

    async fn update_account(
        &self,
        address: &Address,
        account: UpdateSet,
    ) -> Result<()> {
        let body = account.encode().await?;
        let uri = self.build_uri(SYNC_ACCOUNT)?;
        tracing::debug!(uri = %uri, "local_client::update_account");

        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(X_SOS_ACCOUNT_ID, address.to_string())
            .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF)
            .body(body)?;

        let response = {
            let mut transport = self.transport.lock().await;
            transport.call(request.into()).await?
        };
        let status = response.status()?;
        tracing::debug!(status = %status, "local_client::update_account");
        self.error_json(response).await?;
        Ok(())
    }

    async fn fetch_account(&self, address: &Address) -> Result<CreateSet> {
        let uri = self.build_uri(SYNC_ACCOUNT)?;
        tracing::debug!(uri = %uri, "local_client::fetch_account");

        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(X_SOS_ACCOUNT_ID, address.to_string())
            .body(Default::default())?;

        let response = {
            let mut transport = self.transport.lock().await;
            transport.call(request.into()).await?
        };
        let status = response.status()?;
        tracing::debug!(status = %status, "local_client::fetch_account");
        let response = self.error_json(response).await?;
        let bytes = self.read_response_body(response)?;

        Ok(CreateSet::decode(bytes).await?)
    }

    async fn delete_account(&self, address: &Address) -> Result<()> {
        let uri = self.build_uri(SYNC_ACCOUNT)?;
        tracing::debug!(uri = %uri, "local_client::delete_account");

        let request = Request::builder()
            .method(Method::DELETE)
            .uri(uri)
            .header(X_SOS_ACCOUNT_ID, address.to_string())
            .body(Default::default())?;

        let response = {
            let mut transport = self.transport.lock().await;
            transport.call(request.into()).await?
        };
        let status = response.status()?;
        tracing::debug!(status = %status, "local_client::delete_account");
        self.error_json(response).await?;
        Ok(())
    }

    async fn sync_status(&self, address: &Address) -> Result<SyncStatus> {
        let uri = self.build_uri(SYNC_ACCOUNT_STATUS)?;
        tracing::debug!(uri = %uri, "local_client::sync_status");

        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(X_SOS_ACCOUNT_ID, address.to_string())
            .body(Default::default())?;

        let response = {
            let mut transport = self.transport.lock().await;
            transport.call(request.into()).await?
        };
        let status = response.status()?;
        tracing::debug!(status = %status, "local_client::sync_status");
        let response = self.check_response(response).await?;
        Ok(SyncStatus::decode(response.bytes()).await?)
    }

    async fn sync(
        &self,
        address: &Address,
        packet: SyncPacket,
    ) -> Result<SyncPacket> {
        let body = packet.encode().await?;
        let uri = self.build_uri(SYNC_ACCOUNT)?;
        tracing::debug!(uri = %uri, "local_client::sync");

        let request = Request::builder()
            .method(Method::PATCH)
            .uri(uri)
            .header(X_SOS_ACCOUNT_ID, address.to_string())
            .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF)
            .body(body)?;

        let response = {
            let mut transport = self.transport.lock().await;
            transport.call(request.into()).await?
        };
        let status = response.status()?;
        tracing::debug!(status = %status, "local_client::sync");
        let response = self.check_response(response).await?;
        Ok(SyncPacket::decode(response.bytes()).await?)
    }

    async fn scan(
        &self,
        address: &Address,
        request: ScanRequest,
    ) -> Result<ScanResponse> {
        let body = request.encode().await?;
        let uri = self.build_uri(SYNC_ACCOUNT_EVENTS)?;
        tracing::debug!(uri = %uri, "local_client::scan");

        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(X_SOS_ACCOUNT_ID, address.to_string())
            .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF)
            .body(body)?;
        let response = {
            let mut transport = self.transport.lock().await;
            transport.call(request.into()).await?
        };
        let status = response.status()?;
        tracing::debug!(status = %status, "local_client::scan");
        let response = self.check_response(response).await?;
        Ok(ScanResponse::decode(response.bytes()).await?)
    }

    async fn diff(
        &self,
        address: &Address,
        request: DiffRequest,
    ) -> Result<DiffResponse> {
        let body = request.encode().await?;
        let uri = self.build_uri(SYNC_ACCOUNT_EVENTS)?;
        tracing::debug!(uri = %uri, "local_client::diff");

        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(X_SOS_ACCOUNT_ID, address.to_string())
            .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF)
            .body(body)?;
        let response = {
            let mut transport = self.transport.lock().await;
            transport.call(request.into()).await?
        };
        let status = response.status()?;
        tracing::debug!(status = %status, "local_client::diff");
        let response = self.check_response(response).await?;
        Ok(DiffResponse::decode(response.bytes()).await?)
    }

    async fn patch(
        &self,
        address: &Address,
        request: PatchRequest,
    ) -> Result<PatchResponse> {
        let body = request.encode().await?;
        let uri = self.build_uri(SYNC_ACCOUNT_EVENTS)?;
        tracing::debug!(uri = %uri, "local_client::patch");

        let request = Request::builder()
            .method(Method::PATCH)
            .uri(uri)
            .header(X_SOS_ACCOUNT_ID, address.to_string())
            .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF)
            .body(body)?;
        let response = {
            let mut transport = self.transport.lock().await;
            transport.call(request.into()).await?
        };
        let status = response.status()?;
        tracing::debug!(status = %status, "local_client::patch");
        let response = self.check_response(response).await?;
        Ok(PatchResponse::decode(response.bytes()).await?)
    }
}
