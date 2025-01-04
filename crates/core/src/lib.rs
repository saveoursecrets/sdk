//! Core types and constants for the [Save Our Secrets](https://saveoursecrets.com) SDK.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]

mod account;
pub mod commit;
pub mod constants;
pub mod crypto;
mod date_time;
pub mod device;
pub mod encoding;
mod error;
pub mod events;
mod file;
pub mod file_identity;
mod origin;
mod paths;

pub use account::AccountId;
// pub use crypto::*;
pub use date_time::UtcDateTime;
// pub use device::{DevicePublicKey, TrustedDevice};
pub use encoding::{decode, encode};
pub use error::Error;
pub use file::{ExternalFile, ExternalFileName};
pub use origin::Origin;
pub use paths::Paths;
pub use rs_merkle as merkle;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;

use bitflags::bitflags;
use rand::{rngs::OsRng, CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Exposes the default cryptographically secure RNG.
pub fn csprng() -> impl CryptoRng + Rng {
    OsRng
}

/// Identifier for a vault.
pub type VaultId = uuid::Uuid;

/// Identifier for a secret.
pub type SecretId = uuid::Uuid;

/// Secret as an encrypted pair of meta and secret data.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct VaultEntry(pub crypto::AeadPack, pub crypto::AeadPack);

/// Encrypted secret with an associated commit hash.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct VaultCommit(pub commit::CommitHash, pub VaultEntry);

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

bitflags! {
    /// Bit flags for a vault.
    #[derive(Default, Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
    #[serde(transparent)]
    pub struct VaultFlags: u64 {
        /// Indicates this vault should be treated as
        /// the default folder.
        const DEFAULT           =        0b0000000000000001;
        /// Indicates this vault is an identity vault used
        /// to authenticate a user and store delegated folder passwords.
        const IDENTITY          =        0b0000000000000010;
        /// Indicates this vault is to be used as an archive.
        const ARCHIVE           =        0b0000000000000100;
        /// Indicates this vault is to be used for
        /// two-factor authentication.
        const AUTHENTICATOR     =        0b0000000000001000;
        /// Indicates this vault is to be used to store contacts.
        const CONTACT           =        0b0000000000010000;
        /// Indicates this vault is a system vault and should
        /// not be presented to the account holder when listing
        /// available vaults.
        const SYSTEM            =        0b0000000000100000;
        /// Indicates this vault is to be used to store device
        /// specific information such as key shares or device
        /// specific private keys.
        ///
        /// Typically these vaults should also be assigned the
        /// NO_SYNC flag.
        const DEVICE            =        0b0000000001000000;
        /// Indicates this vault should not be synced with
        /// devices owned by the account holder.
        ///
        /// This is useful for storing device specific keys.
        const NO_SYNC           =        0b0000000010000000;
        /// Indicates the folder is intended to be local first.
        const LOCAL             =        0b0000000100000000;
        /// Indicates this vault is shared using asymmetric
        /// encryption.
        const SHARED            =        0b0000001000000000;
    }
}

impl VaultFlags {
    /// Determine if this vault is a default vault.
    pub fn is_default(&self) -> bool {
        self.contains(VaultFlags::DEFAULT)
    }

    /// Determine if this vault is an identity vault.
    pub fn is_identity(&self) -> bool {
        self.contains(VaultFlags::IDENTITY)
    }

    /// Determine if this vault is an archive vault.
    pub fn is_archive(&self) -> bool {
        self.contains(VaultFlags::ARCHIVE)
    }

    /// Determine if this vault is an authenticator vault.
    pub fn is_authenticator(&self) -> bool {
        self.contains(VaultFlags::AUTHENTICATOR)
    }

    /// Determine if this vault is for contacts.
    pub fn is_contact(&self) -> bool {
        self.contains(VaultFlags::CONTACT)
    }

    /// Determine if this vault is for system specific information.
    pub fn is_system(&self) -> bool {
        self.contains(VaultFlags::SYSTEM)
    }

    /// Determine if this vault is for device specific information.
    pub fn is_device(&self) -> bool {
        self.contains(VaultFlags::DEVICE)
    }

    /// Determine if this vault is set to ignore sync
    /// with other devices owned by the account holder.
    pub fn is_sync_disabled(&self) -> bool {
        self.contains(VaultFlags::NO_SYNC)
    }

    /// Determine if this vault is local first.
    pub fn is_local(&self) -> bool {
        self.contains(VaultFlags::LOCAL)
    }

    /// Determine if this vault is shared.
    pub fn is_shared(&self) -> bool {
        self.contains(VaultFlags::SHARED)
    }
}
