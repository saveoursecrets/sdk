//! Types for backup archives.
use serde::{Deserialize, Serialize};
use sos_core::{AccountId, VaultId};
use sos_vault::{Summary, Vault};
use std::collections::HashMap;

/// Vault reference extracted from an archive.
pub type ArchiveItem = (Summary, Vec<u8>);

/// Version information for backup archives.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ManifestVersion {
    /// Version 1 backup archives correspond to the
    /// v1 file system storage.
    ///
    /// A single backup archive includes only one account.
    V1(ManifestVersion1),
    /// Version 2 backup archives include the SQLite
    /// database and external file blobs and may contain
    /// multiple accounts.
    V2,
}

/// Version 1 manifest.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ManifestVersion1 {
    /// Account identifier.
    #[serde(rename = "address")]
    pub account_id: AccountId,

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

/// Manifest used to determine if the archive is supported
/// for import purposes.
#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    /// Backup archive version.
    #[serde(flatten)]
    pub version: ManifestVersion,
    /*
    /// Account identifier.
    #[serde(rename = "address")]
    pub account_id: AccountId,

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
    */
}

/// Buffers of data to restore after selected options
/// have been applied to the data in an archive.
pub struct RestoreTargets {
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
