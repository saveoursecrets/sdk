#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Library to export secrets unencrypted for migration
//! or to import unencrypted data.
//!
//! Used to move between different software providers.

use async_trait::async_trait;

use sos_sdk::{crypto::AccessKey, vault::Vault};

mod error;

pub use error::Error;

/// Result type for the migration library.
pub type Result<T> = std::result::Result<T, Error>;

/// Trait for implementations that can convert data
/// from a third-party provider.
#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait Convert {
    /// Input type for the conversion.
    type Input;

    /// Write the input secrets type to the specified vault.
    async fn convert(
        &self,
        source: Self::Input,
        vault: Vault,
        key: AccessKey,
    ) -> Result<Vault>;
}

pub mod export;
pub mod import;
