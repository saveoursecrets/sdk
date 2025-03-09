//! Parser for the MacOS passwords CSV export.

use async_trait::async_trait;
use serde::Deserialize;
use sos_core::crypto::AccessKey;
use sos_vault::Vault;
use sos_vfs as vfs;
use std::path::{Path, PathBuf};
use tokio::io::AsyncRead;
use url::Url;

use super::{
    GenericCsvConvert, GenericCsvEntry, GenericPasswordRecord, UNTITLED,
};
use crate::{import::read_csv_records, Convert, Result};

/// Record for an entry in a MacOS passwords CSV export.
#[derive(Deserialize)]
pub struct MacPasswordRecord {
    /// The title of the entry.
    #[serde(rename = "Title")]
    pub title: String,
    /// The URL of the entry.
    #[serde(rename = "Url")]
    pub url: Option<Url>,
    /// The username for the entry.
    #[serde(rename = "Username")]
    pub username: String,
    /// The password for the entry.
    #[serde(rename = "Password")]
    pub password: String,
    /// Notes for the entry.
    #[serde(rename = "Notes")]
    pub notes: Option<String>,
    /// OTP auth information for the entry.
    #[serde(rename = "OTPAuth")]
    pub otp_auth: Option<String>,
}

impl From<MacPasswordRecord> for GenericPasswordRecord {
    fn from(value: MacPasswordRecord) -> Self {
        let label = if value.title.is_empty() {
            UNTITLED.to_owned()
        } else {
            value.title
        };

        let url = if let Some(url) = value.url {
            vec![url]
        } else {
            vec![]
        };

        Self {
            label,
            url,
            username: value.username,
            password: value.password,
            otp_auth: value.otp_auth,
            tags: None,
            note: value.notes,
        }
    }
}

impl From<MacPasswordRecord> for GenericCsvEntry {
    fn from(value: MacPasswordRecord) -> Self {
        Self::Password(value.into())
    }
}

/// Parse records from a reader.
pub async fn parse_reader<R: AsyncRead + Unpin + Send>(
    reader: R,
) -> Result<Vec<MacPasswordRecord>> {
    read_csv_records::<MacPasswordRecord, _>(reader).await
}

/// Parse records from a path.
pub async fn parse_path<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<MacPasswordRecord>> {
    parse_reader(vfs::File::open(path).await?).await
}

/// Import a MacOS passwords CSV export into a vault.
pub struct MacPasswordCsv;

#[async_trait]
impl Convert for MacPasswordCsv {
    type Input = PathBuf;

    async fn convert(
        &self,
        source: Self::Input,
        vault: Vault,
        key: &AccessKey,
    ) -> crate::Result<Vault> {
        let records: Vec<GenericCsvEntry> = parse_path(source)
            .await?
            .into_iter()
            .map(|r| r.into())
            .collect();
        GenericCsvConvert.convert(records, vault, key).await
    }
}
