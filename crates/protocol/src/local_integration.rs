//! Local integration is a sync client used to connect to an
//! app running on the same device.
//!
//! Like network-aware accounts it operates on the
//! encrypted data sources so that it is able to communicate
//! over potentially insecure unauthenticated communication
//! channels such as named pipes.
//!
//! Typically, this would be used in the webassembly bindings
//! for a browser extension or other local integration.

use crate::{
    CreateSet, DiffRequest, DiffResponse, Error, Origin, PatchRequest,
    PatchResponse, ScanRequest, ScanResponse, SyncClient, SyncPacket,
    SyncStatus, UpdateSet,
};
use async_trait::async_trait;
use sos_sdk::prelude::LocalAccountSwitcher;
use tokio::sync::RwLock;

/// Local app integration.
pub struct LocalIntegration {
    accounts: RwLock<LocalAccountSwitcher>,
}

impl LocalIntegration {
    /// Create a local app integration.
    pub fn new() -> Self {
        Self {
            accounts: RwLock::new(LocalAccountSwitcher::new()),
        }
    }
}

#[async_trait]
impl SyncClient for LocalIntegration {
    type Error = Error;

    fn origin(&self) -> &Origin {
        unimplemented!(
            "origin is not supported for local integration clients"
        );
    }

    async fn account_exists(&self) -> Result<bool, Self::Error> {
        todo!();
    }

    async fn create_account(
        &self,
        account: CreateSet,
    ) -> Result<(), Self::Error> {
        todo!();
    }

    async fn update_account(
        &self,
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
