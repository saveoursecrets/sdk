//! Types for encrypting recovery data and splitting the secrets
//! for social recovery.
//!
//! Recovery data maps vault identifiers to passwords. Recovery data is
//! encrypted using the private account signing key and the signing key
//! is then split using Shamir's secret sharing (SSS) so that the
//! recovery shares can be distributed amongst trusted parties.
//!
//! This module does not contain any networking or logic for
//! secret share distribution.

mod encoding;
mod error;
mod recovery;

pub use error::Error;
pub use recovery::*;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;
