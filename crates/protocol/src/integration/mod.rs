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
    SyncStatus, UpdateSet, WireEncodeDecode,
};
use async_trait::async_trait;
use http::StatusCode;
use sos_sdk::prelude::{Account, AccountSwitcher, Address};
use std::sync::Arc;
use tokio::sync::RwLock;

mod linked_account;
mod local_client;

pub use linked_account::*;
pub use local_client::*;

/// Account switcher for linked accounts.
pub type LinkedAccountSwitcher = AccountSwitcher<
    <LinkedAccount as Account>::Error,
    <LinkedAccount as Account>::NetworkResult,
    LinkedAccount,
>;

/// Local app integration.
pub struct LocalIntegration {
    origin: Origin,
    accounts: Arc<RwLock<LinkedAccountSwitcher>>,
}

impl LocalIntegration {
    /// Create a local app integration.
    pub fn new(origin: Origin) -> Self {
        Self {
            origin,
            accounts: Arc::new(RwLock::new(LinkedAccountSwitcher::new())),
        }
    }

    /// Clone of the accounts.
    pub fn accounts(&self) -> Arc<RwLock<LocalAccountSwitcher>> {
        self.accounts.clone()
    }

    /// Determine if a local account exists.
    pub async fn local_account_exists(
        &self,
        address: &Address,
    ) -> Result<bool, Error> {
        let accounts = self.accounts.read().await;
        let account = accounts.iter().find(|a| a.address() == address);
        Ok(account.is_some())
    }
}
