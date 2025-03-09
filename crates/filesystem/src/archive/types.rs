//! Types for backup archives.
use serde::{Deserialize, Serialize};
use sos_core::{AccountId, ArchiveManifestVersion, VaultId};
use sos_vault::{Summary, Vault};
use std::collections::HashMap;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
