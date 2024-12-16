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
//!
//! Experimental and may be removed at any time, do not use.

use crate::Result;
use sos_protocol::{Origin, RemoteSync};
use sos_sdk::prelude::{Account, AccountSwitcher, Paths, PublicIdentity};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

mod linked_account;
mod local_client;

pub use linked_account::*;
pub use local_client::*;

/// Account switcher for linked accounts.
pub type LinkedAccountSwitcher = AccountSwitcher<
    LinkedAccount,
    <LinkedAccount as Account>::NetworkResult,
    <LinkedAccount as Account>::Error,
>;

/// Local app integration.
pub struct LocalIntegration {
    accounts: Arc<RwLock<LinkedAccountSwitcher>>,
    client: LocalClient,
}

impl LocalIntegration {
    /// Create a local app integration.
    pub fn new(origin: Origin, transport: ClientTransport) -> Self {
        let transport = Arc::new(Mutex::new(transport));
        let client = LocalClient::new(origin, transport);
        Self {
            accounts: Arc::new(RwLock::new(LinkedAccountSwitcher::new())),
            client,
        }
    }

    /// Accounts managed by this integration.
    pub fn accounts(&self) -> Arc<RwLock<LinkedAccountSwitcher>> {
        self.accounts.clone()
    }

    /// Client used to communicate with the local account.
    pub fn client(&self) -> &LocalClient {
        &self.client
    }

    /// Initialize the accounts list.
    pub async fn initialize_accounts(
        &mut self,
        accounts: Vec<PublicIdentity>,
    ) -> Result<()> {
        let managed_accounts = self.accounts();
        let client = self.client.clone();

        Paths::scaffold(None).await?;

        let mut managed_accounts = managed_accounts.write().await;

        for identity in accounts {
            tracing::info!(address = %identity.address(), "add_account");
            let account = LinkedAccount::new_unauthenticated(
                *identity.address(),
                client.clone(),
                None,
            )
            .await?;

            let paths = account.paths();
            // tracing::info!(paths = ?paths);
            paths.ensure().await?;

            managed_accounts.add_account(account);
        }
        Ok(())
    }

    /// Sync the accounts data.
    pub async fn sync_accounts(&mut self) -> Result<()> {
        let mut accounts = self.accounts.write().await;
        for account in accounts.iter_mut() {
            tracing::info!(address = %account.address(), "sync_account");
            let sync_result = account.sync().await;
            if let Err(e) = sync_result.result {
                tracing::error!(error = %e);
            } else {
                tracing::info!(
                    address = %account.address(),
                    "sync_account::done",
                );
            }
        }
        Ok(())
    }
}
