use serde::{Deserialize, Serialize};
use sos_core::ArchiveManifestVersion;

/// Version 3 manifest.
#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestVersion3 {
    /// Manifest version.
    pub version: ArchiveManifestVersion,
}

impl ManifestVersion3 {
    /// Create a v3 archive manifest.
    pub fn new_v3() -> Self {
        Self {
            version: ArchiveManifestVersion::V3,
        }
    }
}
