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
use serde_with::{serde_as, DisplayFromStr};
use sos_sdk::{constants::MIME_TYPE_PROTOBUF, prelude::Address, url::Url};
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
        // self.error_json(response).await?;
        todo!("handle error status");
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
        // self.error_json(response).await?;
        todo!("handle error status");
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
        // self.error_json(response).await?;
        todo!("handle error status");
        Ok(CreateSet::decode(response.bytes()).await?)
    }

    async fn delete_account(&self) -> Result<()> {
        todo!();
    }

    async fn sync_status(&self) -> Result<SyncStatus> {
        todo!();
    }

    async fn sync(&self, packet: SyncPacket) -> Result<SyncPacket> {
        todo!();
    }

    async fn scan(&self, request: ScanRequest) -> Result<ScanResponse> {
        todo!();
    }

    async fn diff(&self, request: DiffRequest) -> Result<DiffResponse> {
        todo!();
    }

    async fn patch(&self, request: PatchRequest) -> Result<PatchResponse> {
        todo!();
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
#[derive(Debug, Serialize, Deserialize)]
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
