//! Import secrets from other providers and software.
use std::{fmt, path::PathBuf, str::FromStr};

use crate::Error;

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

impl fmt::Display for ImportFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::OnePasswordCsv => "onepassword.csv",
                Self::DashlaneZip => "dashlane.zip",
                Self::BitwardenCsv => "bitwarden.csv",
                Self::ChromeCsv => "chrome.csv",
                Self::FirefoxCsv => "firefox.csv",
                Self::MacosCsv => "macos.csv",
            }
        )
    }
}

impl FromStr for ImportFormat {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "onepassword.csv" => Self::OnePasswordCsv,
            "dashlane.zip" => Self::DashlaneZip,
            "bitwarden.csv" => Self::BitwardenCsv,
            "chrome.csv" => Self::ChromeCsv,
            "firefox.csv" => Self::FirefoxCsv,
            "macos.csv" => Self::MacosCsv,
            _ => todo!(),
        })
    }
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
