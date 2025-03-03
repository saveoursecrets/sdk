#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Core types and constants for the [Save Our Secrets](https://saveoursecrets.com) SDK.

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
mod identity;
mod origin;
mod paths;

pub use account::AccountId;
// pub use crypto::*;
pub use date_time::UtcDateTime;
// pub use device::{DevicePublicKey, TrustedDevice};
pub use encoding::{decode, encode};
pub use error::{AuthenticationError, Error, ErrorExt, StorageError};
pub use file::{ExternalFile, ExternalFileName};
pub use identity::{AccountRef, PublicIdentity};
pub use origin::{Origin, RemoteOrigins};
pub use paths::Paths;
pub use rs_merkle as merkle;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;

use bitflags::bitflags;
use rand::{rngs::OsRng, CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::{fmt, path::Path, str::FromStr};
use uuid::Uuid;

/// Exposes the default cryptographically secure RNG.
pub fn csprng() -> impl CryptoRng + Rng {
    OsRng
}

/// Identifier for a vault.
pub type VaultId = Uuid;

/// Identifier for a secret.
pub type SecretId = Uuid;

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

/// Manifest version for backup archives.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ArchiveManifestVersion {
    /// Version 1 backup archives correspond to the
    /// v1 file system storage but do not include some
    /// additional event logs which were added later
    /// and are optional.
    ///
    /// A single backup archive includes only one account.
    V1 = 1,

    /// Version 2 backup archives correspond to the
    /// v1 file system storage and include all event
    /// logs, preferences and remote origins.
    ///
    /// A single backup archive includes only one account.
    V2 = 2,

    /// Version 3 backup archives include the SQLite
    /// database and external file blobs and may contain
    /// multiple accounts.
    V3 = 3,
}

impl Default for ArchiveManifestVersion {
    // Backwards compatible before we added tracking
    // of backup archive manifest versions.
    //
    // For version 2 and version 3 the version is
    // explicitly added to each manifest file.
    fn default() -> Self {
        Self::V1
    }
}

// Implement serialization manually
impl Serialize for ArchiveManifestVersion {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

// Implement deserialization manually
impl<'de> Deserialize<'de> for ArchiveManifestVersion {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        match value {
            1 => Ok(ArchiveManifestVersion::V1),
            2 => Ok(ArchiveManifestVersion::V2),
            3 => Ok(ArchiveManifestVersion::V3),
            _ => Err(serde::de::Error::custom(
                "invalid archive manifest version",
            )),
        }
    }
}

/// Reference to a folder using an id or a named label.
#[derive(Debug, Clone)]
pub enum FolderRef {
    /// Vault identifier.
    Id(VaultId),
    /// Vault label.
    Name(String),
}

impl fmt::Display for FolderRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id(id) => write!(f, "{}", id),
            Self::Name(name) => write!(f, "{}", name),
        }
    }
}

impl FromStr for FolderRef {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        if let Ok(id) = Uuid::parse_str(s) {
            Ok(Self::Id(id))
        } else {
            Ok(Self::Name(s.to_string()))
        }
    }
}

impl From<VaultId> for FolderRef {
    fn from(value: VaultId) -> Self {
        Self::Id(value)
    }
}
