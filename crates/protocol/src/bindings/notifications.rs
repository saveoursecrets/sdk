include!(concat!(env!("OUT_DIR"), "/notifications.rs"));

use crate::{Error, ProtoBinding, Result};
use sos_core::{commit::CommitHash, AccountId};
use sos_sync::MergeOutcome;

/// Notification sent by the server when changes were made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeNotification {
    /// Account identifier.
    account_id: AccountId,
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
        account_id: &AccountId,
        connection_id: String,
        root: CommitHash,
        outcome: MergeOutcome,
    ) -> Self {
        Self {
            account_id: *account_id,
            connection_id,
            root,
            outcome,
        }
    }

    /// AccountId of the account owner.
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
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

impl From<ChangeNotification>
    for (AccountId, String, CommitHash, MergeOutcome)
{
    fn from(value: ChangeNotification) -> Self {
        (
            value.account_id,
            value.connection_id,
            value.root,
            value.outcome,
        )
    }
}

impl ProtoBinding for ChangeNotification {
    type Inner = WireChangeNotification;
}

impl TryFrom<WireChangeNotification> for ChangeNotification {
    type Error = Error;

    fn try_from(value: WireChangeNotification) -> Result<Self> {
        let account_id: [u8; 20] = value.account_id.as_slice().try_into()?;
        Ok(Self {
            account_id: account_id.into(),
            connection_id: value.connection_id,
            root: value.root.unwrap().try_into()?,
            outcome: value.outcome.unwrap().try_into()?,
        })
    }
}

impl From<ChangeNotification> for WireChangeNotification {
    fn from(value: ChangeNotification) -> WireChangeNotification {
        Self {
            account_id: value.account_id().as_ref().to_vec(),
            connection_id: value.connection_id,
            root: Some(value.root.into()),
            outcome: Some(value.outcome.into()),
        }
    }
}
