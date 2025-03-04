//! Public identity information.
use crate::AccountId;
use crate::Error;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// Public account identity information.
#[typeshare::typeshare]
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct PublicIdentity {
    /// Account identifier.
    account_id: AccountId,
    /// Label for the account.
    ///
    /// This is the name given to the identity vault.
    label: String,
}

impl PublicIdentity {
    /// Create new account information.
    pub fn new(account_id: AccountId, label: String) -> Self {
        Self { account_id, label }
    }

    /// Get the account identifier.
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }

    /// Get the label of this account.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Set the account label.
    pub fn set_label(&mut self, label: String) {
        self.label = label;
    }
}

impl From<&PublicIdentity> for AccountRef {
    fn from(value: &PublicIdentity) -> Self {
        AccountRef::Id(*value.account_id())
    }
}

impl From<PublicIdentity> for AccountRef {
    fn from(value: PublicIdentity) -> Self {
        (&value).into()
    }
}

/// Reference to an account using an address or a named label.
#[derive(Debug, Clone)]
pub enum AccountRef {
    /// Account identifier.
    Id(AccountId),
    /// Account label.
    Name(String),
}

impl fmt::Display for AccountRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id(id) => write!(f, "{}", id),
            Self::Name(name) => write!(f, "{}", name),
        }
    }
}

impl FromStr for AccountRef {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if let Ok(id) = s.parse::<AccountId>() {
            Ok(Self::Id(id))
        } else {
            Ok(Self::Name(s.to_string()))
        }
    }
}
