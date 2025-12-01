//! Parser for the Chrome passwords CSV export.

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
use crate::{Convert, Result, import::read_csv_records};

/// Record for an entry in a Chrome passwords CSV export.
#[derive(Deserialize)]
pub struct ChromePasswordRecord {
    /// The name of the entry.
    pub name: String,
    /// The URL of the entry.
    pub url: Option<String>,
    /// The username for the entry.
    pub username: String,
    /// The password for the entry.
    pub password: String,
    /// The note for the entry.
    pub note: Option<String>,
}

impl From<ChromePasswordRecord> for GenericPasswordRecord {
    fn from(value: ChromePasswordRecord) -> Self {
        let label = if value.name.is_empty() {
            UNTITLED.to_owned()
        } else {
            value.name
        };

        let url = if let Some(url) = value.url {
            let mut websites = Vec::new();
            for u in url.split(",") {
                if let Ok(url) = u.trim().parse::<Url>() {
                    websites.push(url);
                }
            }
            websites
        } else {
            vec![]
        };

        Self {
            label,
            url,
            username: value.username,
            password: value.password,
            otp_auth: None,
            tags: None,
            note: value.note,
        }
    }
}

impl From<ChromePasswordRecord> for GenericCsvEntry {
    fn from(value: ChromePasswordRecord) -> Self {
        Self::Password(value.into())
    }
}

/// Parse records from a reader.
pub async fn parse_reader<R: AsyncRead + Unpin + Send>(
    reader: R,
) -> Result<Vec<ChromePasswordRecord>> {
    read_csv_records::<ChromePasswordRecord, _>(reader).await
}

/// Parse records from a path.
pub async fn parse_path<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<ChromePasswordRecord>> {
    parse_reader(vfs::File::open(path).await?).await
}

/// Import a Chrome passwords CSV export into a vault.
pub struct ChromePasswordCsv;

#[async_trait]
impl Convert for ChromePasswordCsv {
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
