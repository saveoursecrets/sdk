//! Local client sends requests over a local,
//! unauthenticated, insecure communication channel
//! such as IPC.
//!
//! It communicates in the same way as the network-aware
//! client sending only encrypted data in the payloads.

use crate::{
    CreateSet, DiffRequest, DiffResponse, Error, Origin, PatchRequest,
    PatchResponse, Result, ScanRequest, ScanResponse, SyncClient, SyncPacket,
    SyncStatus, UpdateSet,
};
use async_trait::async_trait;
use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use sos_sdk::{prelude::Address, url::Url};
use std::sync::Arc;
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

    /// Build a URL for the local client.
    fn build_url(&self, route: &str) -> Result<Url> {
        Ok(self.origin.url().join(route)?)
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
        let url = self.build_url("api/v1/sync/account")?;

        tracing::debug!(url = %url, "local_client::account_exists");

        let request = TransportRequest {
            method: Method::HEAD,
            url,
            body: None,
        };

        let response = self.transport.send(request).await?;
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
        todo!();
    }

    async fn update_account(
        &self,
        address: &Address,
        account: UpdateSet,
    ) -> Result<()> {
        todo!();
    }

    async fn fetch_account(&self) -> Result<CreateSet> {
        todo!();
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
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct TransportRequest {
    /// Request method.
    #[serde_as(as = "DisplayFromStr")]
    pub method: Method,
    /// Request URL.
    #[serde_as(as = "DisplayFromStr")]
    pub url: Url,
    /// Request body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Vec<u8>>,
}

/// Response received from a local data source.
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct TransportResponse {
    /// Response status code.
    #[serde_as(as = "DisplayFromStr")]
    status: StatusCode,
    /// Response body.
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<Vec<u8>>,
}

impl TransportResponse {
    /// Status code.
    pub fn status(&self) -> StatusCode {
        self.status
    }
}

/// Generic local transport.
#[async_trait]
pub trait LocalTransport {
    /// Send a request over the local transport.
    async fn send(
        &self,
        request: TransportRequest,
    ) -> Result<TransportResponse>;
}
