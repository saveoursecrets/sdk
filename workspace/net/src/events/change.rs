//! Events emitted over by the server to
//! notify connected clients that changes have been made.
use serde::{Deserialize, Serialize};

use sos_sdk::{
    commit::CommitProof,
    events::{Event, WriteEvent},
    signer::ecdsa::Address,
    vault::{secret::SecretId, VaultId},
};

use crate::{Error, Result};

/// Notification sent by the server when changes were made.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChangeNotification {
    /// Account owner address.
    address: Address,
    /// Public key of the caller (noise protocol).
    public_key: Vec<u8>,
}

impl ChangeNotification {
    /// Create a new change notification.
    pub fn new(
        address: &Address,
        public_key: &[u8],
    ) -> Self {
        Self {
            address: *address,
            public_key: public_key.to_vec(),
        }
    }

    /// Address of the account owner.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Public key of the connection that 
    /// made the change.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}
