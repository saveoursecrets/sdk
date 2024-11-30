//! Local client sends requests over a local,
//! unauthenticated, insecure communication channel
//! such as IPC.
//!
//! It communicates in the same way as the network-aware
//! client sending only encrypted data in the payloads.

use crate::{
    CreateSet, DiffRequest, DiffResponse, Error, Origin, PatchRequest,
    PatchResponse, ScanRequest, ScanResponse, SyncClient, SyncPacket,
    SyncStatus, UpdateSet, WireEncodeDecode,
};
use async_trait::async_trait;
use http::StatusCode;
use sos_sdk::prelude::{Account, Address, LocalAccountSwitcher};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Linked account.
pub struct LocalClient {
    origin: Origin,
}

impl LocalClient {
    /// Create a local client.
    pub fn new(origin: Origin) -> Self {
        Self { origin }
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

/*
/// Request that can be sent over a local transport.
pub enum TransportRequest {
    /// Create an account on the remote.
    CreateAccount {
        /// Account address.
        address: Address,
        /// Account data.
        account_data: CreateSet,
    },
}

/// Response received by a local transport.
pub struct TransportResponse {
    /// Response status code.
    pub status: StatusCode,
    /// Response packet.
    pub packet: (),
}

/// Generic local transport.
#[async_trait]
pub trait LocalTransport {
    /// Send a request over the local transport.
    async fn send(&self, request: TransportRequest) -> TransportResponse;
}
*/
