use sos_sdk::{
    commit::CommitHash, signer::ecdsa::Address, sync::MergeOutcome,
};

/// Notification sent by the server when changes were made.
#[derive(Debug)]
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

    /// Merge outcome.
    pub fn outcome(&self) -> &MergeOutcome {
        &self.outcome
    }
}
