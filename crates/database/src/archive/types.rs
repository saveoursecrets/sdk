use serde::{Deserialize, Serialize};

/// Version 3 manifest.
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ManifestVersion3 {
    /// Database file.
    pub database: String,
}
