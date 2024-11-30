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
use sos_sdk::prelude::{Account, Address, LocalAccountSwitcher};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Local app integration.
pub struct LocalIntegration {
    origin: Origin,
    accounts: Arc<RwLock<LocalAccountSwitcher>>,
}

impl LocalIntegration {
    /// Create a local app integration.
    pub fn new(origin: Origin) -> Self {
        Self {
            origin,
            accounts: Arc::new(RwLock::new(LocalAccountSwitcher::new())),
        }
    }

    /// Clone of the accounts.
    pub fn accounts(&self) -> Arc<RwLock<LocalAccountSwitcher>> {
        self.accounts.clone()
    }
}

#[async_trait]
impl SyncClient for LocalIntegration {
    type Error = Error;

    fn origin(&self) -> &Origin {
        &self.origin
    }

    async fn account_exists(
        &self,
        address: &Address,
    ) -> Result<bool, Self::Error> {
        let accounts = self.accounts.read().await;
        let account = accounts.iter().find(|a| a.address() == address);
        Ok(account.is_some())
    }

    async fn create_account(
        &self,
        address: &Address,
        account: CreateSet,
    ) -> Result<(), Self::Error> {
        unimplemented!("local integrations cannot create accounts on remote");
    }

    async fn update_account(
        &self,
        address: &Address,
        account: UpdateSet,
    ) -> Result<(), Self::Error> {
        unimplemented!("local integrations cannot update accounts on remote");
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
