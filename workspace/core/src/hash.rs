//! Hash utility types and functions.
use serde::{Deserialize, Serialize};
use std::fmt;

/// Newtype for a 32 byte hash that provides a hexadecimal
/// display implementation.
#[derive(
    Default, Debug, Copy, Clone, Eq, PartialEq, Serialize, Deserialize,
)]
pub struct CommitHash(pub [u8; 32]);

impl AsRef<[u8; 32]> for CommitHash {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl CommitHash {
    /// Get a copy of the underlying bytes for the commit hash.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl From<CommitHash> for [u8; 32] {
    fn from(value: CommitHash) -> Self {
        value.0
    }
}

impl fmt::Display for CommitHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}
