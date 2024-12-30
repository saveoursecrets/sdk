//! Core types and constants for the Save Our Secrets SDK.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

pub mod commit;
pub mod constants;
mod error;
mod file;
mod origin;

pub use error::Error;
pub use file::{ExternalFile, ExternalFileName};
pub use origin::Origin;
pub use rs_merkle as merkle;

/// Result type for the library.
pub type Result<T> = std::result::Result<T, Error>;

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Identifier for a vault.
pub type VaultId = uuid::Uuid;

/// Identifier for a secret.
pub type SecretId = uuid::Uuid;

/// Path to a secret.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretPath(pub VaultId, pub SecretId);

impl SecretPath {
    /// Folder identifier.
    pub fn folder_id(&self) -> &VaultId {
        &self.0
    }

    /// Secret identifier.
    pub fn secret_id(&self) -> &SecretId {
        &self.1
    }
}

/// Infallibly compute the base file name from a path.
///
/// If no file name is available the returned value is the
/// empty string.
pub fn basename(path: impl AsRef<Path>) -> String {
    path.as_ref()
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned()
}

/// Guess the MIME type of a path.
///
/// This implementation supports some more types
/// that are not in the the mime_guess library that
/// we also want to recognize.
pub fn guess_mime(path: impl AsRef<Path>) -> Result<String> {
    if let Some(extension) = path.as_ref().extension() {
        let fixed = match extension.to_string_lossy().as_ref() {
            "heic" => Some("image/heic".to_string()),
            "heif" => Some("image/heif".to_string()),
            "avif" => Some("image/avif".to_string()),
            _ => None,
        };

        if let Some(fixed) = fixed {
            return Ok(fixed);
        }
    }
    let mime = mime_guess::from_path(&path)
        .first_or(mime_guess::mime::APPLICATION_OCTET_STREAM)
        .to_string();
    Ok(mime)
}
