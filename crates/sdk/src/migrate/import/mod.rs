//! Import secrets from other providers and software.
use crate::migrate::{Error, Result};
use enum_iterator::Sequence;
use futures::StreamExt;
use serde::de::DeserializeOwned;
use std::{fmt, path::PathBuf, str::FromStr};
use tokio::io::AsyncRead;

pub mod csv;

#[cfg(all(target_os = "macos", feature = "keychain-access"))]
pub mod keychain;

pub(crate) async fn read_csv_records<
    T: DeserializeOwned,
    R: AsyncRead + Unpin + Send,
>(
    reader: R,
) -> Result<Vec<T>> {
    let mut rows = Vec::new();
    let mut rdr = csv_async::AsyncReaderBuilder::new()
        .flexible(true)
        .create_deserializer(reader);
    let mut records = rdr.deserialize::<T>();
    while let Some(record) = records.next().await {
        let record = record?;
        rows.push(record);
    }
    Ok(rows)
}

/// File formats supported for import.
#[derive(Debug, Clone, Sequence)]
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
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "onepassword.csv" => Self::OnePasswordCsv,
            "dashlane.zip" => Self::DashlaneZip,
            "bitwarden.csv" => Self::BitwardenCsv,
            "chrome.csv" => Self::ChromeCsv,
            "firefox.csv" => Self::FirefoxCsv,
            "macos.csv" => Self::MacosCsv,
            _ => return Err(Error::UnknownImportFormat(s.to_owned())),
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
