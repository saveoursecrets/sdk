//! Local integration is a client used to connect to an
//! app running locally.
//!
//! It's API operates on the encrypted representation of the
//! underlying data sources so that it is able to communicate
//! over potentially insecure unauthenticated communication
//! channels such as named pipes.
//!
//! It is transport-agnostic and provides an API for syncing
//! local account data. Typically, this would be used in
//! the webassembly bindings for a browser extension.

use crate::{CreateSet, Result};
use sos_sdk::prelude::LocalAccountSwitcher;

/// Local app integration.
pub struct LocalIntegration {
    accounts: LocalAccountSwitcher,
}

impl LocalIntegration {
    /// Create a local app integration.
    pub fn new() -> Self {
        Self {
            accounts: LocalAccountSwitcher::new(),
        }
    }

    /// Create an account from the encrypted contents.
    pub fn create_account(&mut self, account_data: CreateSet) -> Result<()> {
        todo!();
    }
}
