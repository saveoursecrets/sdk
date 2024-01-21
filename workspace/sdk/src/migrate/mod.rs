#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Export and import unencrypted data.
//!
//! Used to move between different apps.

use async_trait::async_trait;

use crate::{crypto::AccessKey, vault::Vault};

mod error;

pub use error::Error;

/// Result type for the migration library.
pub type Result<T> = std::result::Result<T, Error>;

/// Trait for implementations that can convert data
/// from a third-party provider.
#[async_trait]
pub trait Convert {
    /// Input type for the conversion.
    type Input;

    /// Write the input secrets to the given vault.
    async fn convert(
        &self,
        source: Self::Input,
        vault: Vault,
        key: &AccessKey,
    ) -> crate::Result<Vault>;
}

pub mod export;
pub mod import;
