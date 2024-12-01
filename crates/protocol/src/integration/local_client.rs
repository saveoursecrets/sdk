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
    CreateSet, DiffRequest, DiffResponse, Error, Origin, PatchRequest,
    PatchResponse, Result, ScanRequest, ScanResponse, SyncClient, SyncPacket,
    SyncStatus, UpdateSet, WireEncodeDecode,
};
use async_trait::async_trait;
use bytes::Bytes;
use http::{
    header::CONTENT_TYPE, Method, Request, Response, StatusCode, Uri,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{serde_as, DisplayFromStr};
use sos_sdk::{
    constants::{MIME_TYPE_JSON, MIME_TYPE_PROTOBUF},
    prelude::Address,
    url::Url,
};
use std::{collections::HashMap, sync::Arc};
use tracing::instrument;

type ClientTransport = Box<dyn LocalTransport + Send + Sync + 'static>;

/// Linked account.
#[derive(Clone)]
pub struct LocalClient {
    origin: Origin,
    transport: Arc<ClientTransport>,
}

impl LocalClient {
    /// Create a local client.
    pub fn new(origin: Origin, transport: Arc<ClientTransport>) -> Self {
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
        response: TransportResponse,
    ) -> Result<TransportResponse> {
        let status = response.status();
        let content_type = response.content_type();
        match (status, content_type) {
            // OK with the correct MIME type can be handled
            (http::StatusCode::OK, Some(content_type)) => {
                if content_type == MIME_TYPE_PROTOBUF {
                    Ok(response)
                } else {
                    Err(Error::ContentType(
                        content_type.to_owned(),
                        MIME_TYPE_PROTOBUF.to_string(),
                    ))
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
        response: TransportResponse,
    ) -> Result<TransportResponse> {
        let status = response.status();
        if !status.is_success() {
            if response.is_json() {
                let value: Value = serde_json::from_slice(&response.body)?;
                Err(Error::ResponseJson(status, value))
            } else {
                Err(Error::ResponseCode(status))
            }
        } else {
            Ok(response)
        }
    }
}

#[async_trait]
impl SyncClient for LocalClient {
    type Error = Error;

    fn origin(&self) -> &Origin {
        &self.origin
    }

    #[instrument(skip(self))]
    async fn account_exists(&self, address: &Address) -> Result<bool> {
        let uri = self.build_uri("api/v1/sync/account")?;
        tracing::debug!(uri = %uri, "local_client::account_exists");

        let request = Request::builder()
            .method(Method::HEAD)
            .uri(uri)
            .body(Default::default())?;

        let response = self.transport.call(request.into()).await?;
        let status = response.status();
        tracing::debug!(status = %status, "local_client::account_exists");
        let exists = match status {
            StatusCode::OK => true,
            StatusCode::NOT_FOUND => false,
            _ => {
                return Err(Error::ResponseCode(status));
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
        let uri = self.build_uri("api/v1/sync/account")?;
        tracing::debug!(uri = %uri, "local_client::create_account");

        let request = Request::builder()
            .method(Method::PUT)
            .uri(uri)
            .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF)
            .body(body)?;

        let response = self.transport.call(request.into()).await?;
        let status = response.status();
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
        let uri = self.build_uri("api/v1/sync/account")?;
        tracing::debug!(uri = %uri, "local_client::update_account");

        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF)
            .body(body)?;

        let response = self.transport.call(request.into()).await?;
        let status = response.status();
        tracing::debug!(status = %status, "local_client::update_account");
        self.error_json(response).await?;
        Ok(())
    }

    async fn fetch_account(&self) -> Result<CreateSet> {
        let uri = self.build_uri("api/v1/sync/account")?;
        tracing::debug!(uri = %uri, "local_client::fetch_account");

        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Default::default())?;

        let response = self.transport.call(request.into()).await?;
        let status = response.status();
        tracing::debug!(status = %status, "local_client::fetch_account");
        let response = self.error_json(response).await?;
        Ok(CreateSet::decode(response.bytes()).await?)
    }

    async fn delete_account(&self) -> Result<()> {
        let uri = self.build_uri("api/v1/sync/account")?;
        tracing::debug!(uri = %uri, "local_client::delete_account");

        let request = Request::builder()
            .method(Method::DELETE)
            .uri(uri)
            .body(Default::default())?;

        let response = self.transport.call(request.into()).await?;
        let status = response.status();
        tracing::debug!(status = %status, "local_client::delete_account");
        self.error_json(response).await?;
        Ok(())
    }

    async fn sync_status(&self) -> Result<SyncStatus> {
        let uri = self.build_uri("api/v1/sync/account/status")?;
        tracing::debug!(uri = %uri, "local_client::sync_status");

        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Default::default())?;

        let response = self.transport.call(request.into()).await?;
        let status = response.status();
        tracing::debug!(status = %status, "local_client::sync_status");
        let response = self.check_response(response).await?;
        Ok(SyncStatus::decode(response.bytes()).await?)
    }

    async fn sync(&self, packet: SyncPacket) -> Result<SyncPacket> {
        let body = packet.encode().await?;
        let uri = self.build_uri("api/v1/sync/account")?;
        tracing::debug!(uri = %uri, "local_client::sync");

        let request = Request::builder()
            .method(Method::PATCH)
            .uri(uri)
            .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF)
            .body(body)?;

        let response = self.transport.call(request.into()).await?;
        let status = response.status();
        tracing::debug!(status = %status, "local_client::sync");
        let response = self.check_response(response).await?;
        Ok(SyncPacket::decode(response.bytes()).await?)
    }

    async fn scan(&self, request: ScanRequest) -> Result<ScanResponse> {
        let body = request.encode().await?;
        let uri = self.build_uri("api/v1/sync/account/events")?;
        tracing::debug!(uri = %uri, "local_client::scan");

        let request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF)
            .body(body)?;
        let response = self.transport.call(request.into()).await?;
        let status = response.status();
        tracing::debug!(status = %status, "local_client::scan");
        let response = self.check_response(response).await?;
        Ok(ScanResponse::decode(response.bytes()).await?)
    }

    async fn diff(&self, request: DiffRequest) -> Result<DiffResponse> {
        let body = request.encode().await?;
        let uri = self.build_uri("api/v1/sync/account/events")?;
        tracing::debug!(uri = %uri, "local_client::diff");

        let request = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF)
            .body(body)?;
        let response = self.transport.call(request.into()).await?;
        let status = response.status();
        tracing::debug!(status = %status, "local_client::diff");
        let response = self.check_response(response).await?;
        Ok(DiffResponse::decode(response.bytes()).await?)
    }

    async fn patch(&self, request: PatchRequest) -> Result<PatchResponse> {
        let body = request.encode().await?;
        let uri = self.build_uri("api/v1/sync/account/events")?;
        tracing::debug!(uri = %uri, "local_client::patch");

        let request = Request::builder()
            .method(Method::PATCH)
            .uri(uri)
            .header(CONTENT_TYPE, MIME_TYPE_PROTOBUF)
            .body(body)?;
        let response = self.transport.call(request.into()).await?;
        let status = response.status();
        tracing::debug!(status = %status, "local_client::patch");
        let response = self.check_response(response).await?;
        Ok(PatchResponse::decode(response.bytes()).await?)
    }
}

/// Request that can be sent to a local data source.
///
/// Supports serde so this type is compatible with the
/// browser extension which transfers JSON via the
/// native messaging API.
///
/// The body will usually be protobuf-encoded binary data.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportRequest {
    /// Request method.
    #[serde_as(as = "DisplayFromStr")]
    pub method: Method,
    /// Request URL.
    #[serde_as(as = "DisplayFromStr")]
    pub uri: Uri,
    /// Request headers.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, Vec<String>>,
    /// Request body.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub body: Vec<u8>,
}

impl From<Request<Vec<u8>>> for TransportRequest {
    fn from(value: Request<Vec<u8>>) -> Self {
        let (parts, body) = value.into_parts();

        let mut headers = HashMap::new();
        for (key, value) in parts.headers.iter() {
            let entry = headers.entry(key.to_string()).or_insert(vec![]);
            entry.push(value.to_str().unwrap().to_owned());
        }

        Self {
            method: parts.method,
            uri: parts.uri,
            headers,
            body,
        }
    }
}

impl TryFrom<TransportRequest> for Request<Vec<u8>> {
    type Error = Error;

    fn try_from(value: TransportRequest) -> Result<Self> {
        todo!();
    }
}

/// Response received from a local data source.
///
/// Supports serde so this type is compatible with the
/// browser extension which transfers JSON via the
/// native messaging API.
///
/// The body will usually be protobuf-encoded binary data.
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct TransportResponse {
    /// Response status code.
    #[serde_as(as = "DisplayFromStr")]
    status: StatusCode,
    /// Response headers.
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, Vec<String>>,
    /// Response body.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    body: Vec<u8>,
}

impl From<Response<Vec<u8>>> for TransportResponse {
    fn from(value: Response<Vec<u8>>) -> Self {
        let (parts, body) = value.into_parts();

        let mut headers = HashMap::new();
        for (key, value) in parts.headers.iter() {
            let entry = headers.entry(key.to_string()).or_insert(vec![]);
            entry.push(value.to_str().unwrap().to_owned());
        }

        Self {
            status: parts.status,
            headers,
            body,
        }
    }
}

impl TransportResponse {
    /// Status code.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Extract a content type header.
    pub fn content_type(&self) -> Option<&str> {
        if let Some(values) = self.headers.get(CONTENT_TYPE.as_str()) {
            values.first().map(|v| v.as_str())
        } else {
            None
        }
    }

    /// Determine if this response is JSON.
    pub fn is_json(&self) -> bool {
        if let Some(values) = self.headers.get(CONTENT_TYPE.as_str()) {
            values
                .iter()
                .find(|v| v.as_str() == MIME_TYPE_JSON)
                .is_some()
        } else {
            false
        }
    }

    /// Convert the body to bytes.
    pub fn bytes(self) -> Bytes {
        self.body.into()
    }
}

/// Generic local transport.
#[async_trait]
pub trait LocalTransport {
    /// Send a request over the local transport.
    async fn call(
        &self,
        request: TransportRequest,
    ) -> Result<TransportResponse>;
}
