include!(concat!(env!("OUT_DIR"), "/notifications.rs"));

use crate::{Error, MergeOutcome, ProtoBinding, Result};
use sos_sdk::{commit::CommitHash, signer::ecdsa::Address};

/// Notification sent by the server when changes were made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeNotification {
    /// Account owner address.
    address: Address,
    /// Connection identifier that made the change.
    connection_id: String,
    /// Root commit for the entire account.
    root: CommitHash,
    /// Merge outcome.
    outcome: MergeOutcome,
}

impl ChangeNotification {
    /// Create a new change notification.
    pub fn new(
        address: &Address,
        connection_id: String,
        root: CommitHash,
        outcome: MergeOutcome,
    ) -> Self {
        Self {
            address: *address,
            connection_id,
            root,
            outcome,
        }
    }

    /// Address of the account owner.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Connection identifier.
    pub fn connection_id(&self) -> &str {
        &self.connection_id
    }

    /// Account root commit hash.
    pub fn root(&self) -> &CommitHash {
        &self.root
    }

    /// Merge outcome.
    pub fn outcome(&self) -> &MergeOutcome {
        &self.outcome
    }
}

impl ProtoBinding for ChangeNotification {
    type Inner = WireChangeNotification;
}

impl TryFrom<WireChangeNotification> for ChangeNotification {
    type Error = Error;

    fn try_from(value: WireChangeNotification) -> Result<Self> {
        let address: [u8; 20] = value.address.as_slice().try_into()?;
        Ok(Self {
            address: address.into(),
            connection_id: value.connection_id,
            root: value.root.unwrap().try_into()?,
            outcome: value.outcome.unwrap().try_into()?,
        })
    }
}

impl From<ChangeNotification> for WireChangeNotification {
    fn from(value: ChangeNotification) -> WireChangeNotification {
        Self {
            address: value.address().as_ref().to_vec(),
            connection_id: value.connection_id,
            root: Some(value.root.into()),
            outcome: Some(value.outcome.into()),
        }
    }
}
