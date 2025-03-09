use crate::{Error, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// Account identifier.
///
/// String encoding starts with 0x and is followed with
/// 20 bytes hex-encoded.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, Hash, Eq, PartialEq)]
#[serde(try_from = "String", into = "String")]
pub struct AccountId([u8; 20]);

impl AccountId {
    /// Create a random account identifier.
    pub fn random() -> Self {
        let mut rng = crate::csprng();
        Self(rng.gen())
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl Default for AccountId {
    fn default() -> Self {
        Self([0u8; 20])
    }
}

impl AsRef<[u8]> for AccountId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 20]> for AccountId {
    fn from(value: [u8; 20]) -> Self {
        Self(value)
    }
}

impl FromStr for AccountId {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if !s.starts_with("0x") {
            return Err(Error::BadAccountIdPrefix);
        }
        let bytes = hex::decode(&s[2..])?;
        let buffer: [u8; 20] = bytes.as_slice().try_into()?;
        Ok(AccountId(buffer))
    }
}

impl From<AccountId> for String {
    fn from(value: AccountId) -> String {
        value.to_string()
    }
}

impl From<AccountId> for [u8; 20] {
    fn from(value: AccountId) -> [u8; 20] {
        value.0
    }
}

impl TryFrom<String> for AccountId {
    type Error = Error;
    fn try_from(value: String) -> Result<Self> {
        <AccountId as FromStr>::from_str(&value)
    }
}
