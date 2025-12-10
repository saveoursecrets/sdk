use serde::{Deserialize, Serialize};
use sos_core::{ArchiveManifestVersion, commit::CommitHash};

/// Version 3 manifest.
#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestVersion3 {
    /// Manifest version.
    pub version: ArchiveManifestVersion,
    /// Checksum of the database file (SHA256).
    pub checksum: CommitHash,
}

impl ManifestVersion3 {
    /// Create a v3 archive manifest.
    pub fn new_v3() -> Self {
        Self {
            version: ArchiveManifestVersion::V3,
            checksum: Default::default(),
        }
    }
}
