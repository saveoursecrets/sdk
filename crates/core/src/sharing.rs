//! Types for public key infrastructure (PKI) and folder sharing.
use crate::{Error, Result};

/// Recipient is a participant in a shared folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recipient {
    /// Recipient name.
    pub name: String,
    /// Optional email.
    pub email: Option<String>,
    /// Public key.
    pub public_key: age::x25519::Recipient,
}

/// Status of a folder invite.
#[derive(Debug, Copy, Clone)]
#[repr(u8)]
pub enum InviteStatus {
    /// Pending invite.
    Pending = 0,
    /// Accepted invite.
    Accepted = 1,
    /// Declined invite.
    Declined = 2,
}

impl TryFrom<i64> for InviteStatus {
    type Error = Error;

    fn try_from(value: i64) -> Result<Self> {
        Ok(match value {
            0 => Self::Pending,
            1 => Self::Accepted,
            2 => Self::Declined,
            _ => return Err(Error::UnknownInviteStatus(value)),
        })
    }
}
