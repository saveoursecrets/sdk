//! Events emitted over by the server to
//! notify connected clients that changes have been made.
use serde::{Deserialize, Serialize};

use sos_sdk::signer::ecdsa::Address;

/// Notification sent by the server when changes were made.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChangeNotification {
    /// Account owner address.
    address: Address,
}

impl ChangeNotification {
    /// Create a new change notification.
    pub fn new(address: &Address) -> Self {
        Self { address: *address }
    }

    /// Address of the account owner.
    pub fn address(&self) -> &Address {
        &self.address
    }
}
