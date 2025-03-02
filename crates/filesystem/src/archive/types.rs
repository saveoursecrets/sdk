//! Types for backup archives.
use serde::{Deserialize, Serialize};
use sos_core::{AccountId, ArchiveManifestVersion, SecretId, VaultId};
use sos_vault::{Summary, Vault};
use std::{collections::HashMap, path::PathBuf};
use uuid::Uuid;

/// Vault reference extracted from an archive.
pub(crate) type ArchiveItem = (Summary, Vec<u8>);

/// Version 1 or 2 manifest.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ManifestVersion1 {
    /// Account identifier.
    #[serde(rename = "address")]
    pub account_id: AccountId,

    /// Manifest version.
    ///
    /// When a manifest version is not set it should be assumed
    /// to be V1.
    pub version: Option<ArchiveManifestVersion>,

    /// Checksum of the identity vault.
    pub checksum: String,

    /// Map of vault identifiers to checksums.
    pub vaults: HashMap<VaultId, String>,

    /// Account events checksum.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,

    /// Device vault and events checksums.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devices: Option<(String, String)>,

    /// File events checksum.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files: Option<String>,

    /// Account-specific preferences.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferences: Option<String>,

    /// Remote server settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remotes: Option<String>,
}

impl ManifestVersion1 {
    /// Create a new manifest set to version 2.
    pub fn new_v2() -> Self {
        let mut manifest = ManifestVersion1::default();
        manifest.version = Some(ArchiveManifestVersion::V2);
        manifest
    }
}

/// Get the path to the file storage directory for the given
/// account address.
type ExtractFilesBuilder =
    Box<dyn Fn(&AccountId) -> Option<PathBuf> + Send + Sync>;

/// Known path or builder for a files directory.
///
/// When extracting an archive to restore an account a user
/// maybe authenticated. If the user is authenticated the file
/// extraction directory can be determined ahead of time, but
/// if we don't have an authenticated user then the files directory
/// should be determined by the address extracted from the archive
/// manifest.
pub enum ExtractFilesLocation {
    /// Known path for the files directory.
    Path(PathBuf),
    /// Builder for the files directory.
    Builder(ExtractFilesBuilder),
}

/// Options for a restore operation.
#[derive(Default)]
#[deprecated]
pub struct RestoreOptions {
    /// Vaults that the user selected to be imported.
    pub selected: Vec<Summary>,
    /// Target directory for files.
    pub files_dir: Option<ExtractFilesLocation>,
}

/// Options to use when building an account manifest.
pub struct AccountManifestOptions {
    /// Ignore vaults with the NO_SYNC flag (default: `true`).
    pub no_sync: bool,
}

impl Default for AccountManifestOptions {
    fn default() -> Self {
        Self { no_sync: true }
    }
}

/// Manifest of all the data in an account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AccountManifest {
    /// Identifier for this manifest.
    pub id: Uuid,
    /// Account address.
    pub address: AccountId,
    /// Manifest entries.
    pub entries: Vec<ManifestEntry>,
}

impl AccountManifest {
    /// Create a new account manifest.
    pub fn new(address: AccountId) -> Self {
        Self {
            id: Uuid::new_v4(),
            address,
            entries: Vec::new(),
        }
    }
}

/// Account manifest entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum ManifestEntry {
    /// Identity vault.
    Identity {
        /// Identifier for this entry.
        id: Uuid,
        /// Label for the entry.
        label: String,
        /// Size of the file in bytes.
        size: u64,
        /// Checksum of the file data (SHA256).
        checksum: [u8; 32],
    },
    /// Folder vault.
    Vault {
        /// Identifier for this entry.
        id: Uuid,
        /// Label for the entry.
        label: String,
        /// Size of the file in bytes.
        size: u64,
        /// Checksum of the file data (SHA256).
        checksum: [u8; 32],
    },
    /// External file storage.
    File {
        /// Identifier for this entry.
        id: Uuid,
        /// Label for the entry.
        label: String,
        /// Size of the file in bytes.
        size: u64,
        /// Checksum of the file data (SHA256).
        checksum: [u8; 32],
        /// Vault identifier.
        vault_id: VaultId,
        /// Secret identifier.
        secret_id: SecretId,
    },
}

impl ManifestEntry {
    /// Get the identifier for this entry.
    pub fn id(&self) -> &Uuid {
        match self {
            Self::Identity { id, .. } => id,
            Self::Vault { id, .. } => id,
            Self::File { id, .. } => id,
        }
    }

    /// Get the checksum for this entry.
    pub fn checksum(&self) -> [u8; 32] {
        match self {
            Self::Identity { checksum, .. } => *checksum,
            Self::Vault { checksum, .. } => *checksum,
            Self::File { checksum, .. } => *checksum,
        }
    }

    /// Get the label for this entry.
    pub fn label(&self) -> &str {
        match self {
            Self::Identity { label, .. } => label,
            Self::Vault { label, .. } => label,
            Self::File { label, .. } => label,
        }
    }
}

/// Buffers of data to restore after selected options
/// have been applied to the data in an archive.
pub(crate) struct RestoreTargets {
    /// The manifest extracted from the archive.
    pub manifest: ManifestVersion1,
    /// Archive item for the identity vault.
    pub identity: ArchiveItem,
    /// List of vaults to restore.
    pub vaults: Vec<(Vec<u8>, Vault)>,
    /// Account events.
    pub account: Option<Vec<u8>>,
    /// Device vault and events.
    pub devices: Option<(Vec<u8>, Vec<u8>)>,
    /// File events.
    pub files: Option<Vec<u8>>,
    /// Account-specific preferences.
    pub preferences: Option<Vec<u8>>,
    /// Remote server origins.
    pub remotes: Option<Vec<u8>>,
}
