//! Import secrets from other providers and software.
use std::path::PathBuf;

pub mod csv;
#[cfg(target_os = "macos")]
pub mod keychain;

/// File formats supported for import.
#[derive(Debug, Clone)]
pub enum ImportFormat {
    /// 1Password CSV file.
    OnePasswordCsv,
    /// Dashlane zip archive.
    DashlaneZip,
    /// Bitwarden CSV file.
    BitwardenCsv,
    /// Chrome CSV file.
    ChromeCsv,
    /// Firefox CSV file.
    FirefoxCsv,
    /// MacOS CSV file.
    MacosCsv,
}

/// Target for an import operation.
#[derive(Debug)]
pub struct ImportTarget {
    /// Expected file format.
    pub format: ImportFormat,
    /// Path to the file.
    pub path: PathBuf,
    /// Name for the folder.
    pub folder_name: String,
}
