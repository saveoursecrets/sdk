//! Local client sends requests over a local,
//! unauthenticated, insecure communication channel
//! such as IPC.
//!
//! It communicates in the same way as the network-aware
//! client sending only encrypted data in the payloads.

use crate::{
    CreateSet, DiffRequest, DiffResponse, Error, Origin, PatchRequest,
    PatchResponse, ScanRequest, ScanResponse, SyncClient, SyncPacket,
    SyncStatus, UpdateSet,
};
use async_trait::async_trait;
use http::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use sos_sdk::{prelude::Address, url::Url};

type ClientTransport = Box<dyn LocalTransport + Send + Sync + 'static>;

/// Linked account.
pub struct LocalClient {
    origin: Origin,
    transport: ClientTransport,
}

impl LocalClient {
    /// Create a local client.
    pub fn new(origin: Origin, transport: ClientTransport) -> Self {
        Self { origin, transport }
    }
}

#[async_trait]
impl SyncClient for LocalClient {
    type Error = Error;

    fn origin(&self) -> &Origin {
        &self.origin
    }

    async fn account_exists(
        &self,
        address: &Address,
    ) -> Result<bool, Self::Error> {
        todo!();
    }

    async fn create_account(
        &self,
        address: &Address,
        account: CreateSet,
    ) -> Result<(), Self::Error> {
        todo!();
    }

    async fn update_account(
        &self,
        address: &Address,
        account: UpdateSet,
    ) -> Result<(), Self::Error> {
        todo!();
    }

    async fn fetch_account(&self) -> Result<CreateSet, Self::Error> {
        todo!();
    }

    async fn delete_account(&self) -> Result<(), Self::Error> {
        todo!();
    }

    async fn sync_status(&self) -> Result<SyncStatus, Self::Error> {
        todo!();
    }

    async fn sync(
        &self,
        packet: SyncPacket,
    ) -> Result<SyncPacket, Self::Error> {
        todo!();
    }

    async fn scan(
        &self,
        request: ScanRequest,
    ) -> Result<ScanResponse, Self::Error> {
        todo!();
    }

    async fn diff(
        &self,
        request: DiffRequest,
    ) -> Result<DiffResponse, Self::Error> {
        todo!();
    }

    async fn patch(
        &self,
        request: PatchRequest,
    ) -> Result<PatchResponse, Self::Error> {
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
    #[serde(skip_serializing = "Option::is_none")]
    pub body: Option<Vec<u8>>,
}

/// Response received from a local data source.
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct TransportResponse {
    /// Response status code.
    #[serde_as(as = "DisplayFromStr")]
    pub status: StatusCode,
    /// Response body.
    #[serde(skip_serializing = "Option::is_none")]
    pub body: Option<Vec<u8>>,
}

/// Generic local transport.
#[async_trait]
pub trait LocalTransport {
    /// Send a request over the local transport.
    async fn send(&self, request: TransportRequest) -> TransportResponse;
}
