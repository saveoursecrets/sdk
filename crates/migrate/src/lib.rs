//! Export and import unencrypted data for the [Save Our Secrets](https://saveoursecrets.com) SDK.
//!
//! Used to move between different apps.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

use async_trait::async_trait;
use sos_sdk::{crypto::AccessKey, vault::Vault};

#[cfg(feature = "authenticator")]
mod authenticator;
mod error;

#[cfg(feature = "authenticator")]
pub use authenticator::*;
pub use error::Error;

/// Result type for the migration library.
pub(crate) type Result<T> = std::result::Result<T, Error>;

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

#[cfg(feature = "export")]
pub mod export;
#[cfg(feature = "import")]
pub mod import;
