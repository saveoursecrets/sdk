//! Parser for the Firefox passwords CSV export.

use async_trait::async_trait;
use serde::Deserialize;
use sos_core::crypto::AccessKey;
use sos_vault::Vault;
use sos_vfs as vfs;
use std::path::{Path, PathBuf};
use tokio::io::AsyncRead;
use url::Url;

use super::{GenericCsvConvert, GenericCsvEntry, GenericPasswordRecord};
use crate::{import::read_csv_records, Convert, Result};

/// Record for an entry in a Firefox passwords CSV export.
#[derive(Deserialize)]
pub struct FirefoxPasswordRecord {
    /// The URL of the entry.
    pub url: Url,
    /// The username for the entry.
    pub username: String,
    /// The password for the entry.
    pub password: String,
    /// The HTTP realm for the entry.
    #[serde(rename = "httpRealm")]
    pub http_realm: String,
    /// The form action origin for the entry.
    #[serde(rename = "formActionOrigin")]
    pub form_action_origin: String,
    /// The guid for the entry.
    pub guid: String,
    /// The time created for the entry.
    #[serde(rename = "timeCreated")]
    pub time_created: String,
    /// The time last used for the entry.
    #[serde(rename = "timeLastUsed")]
    pub time_last_used: String,
    /// The time password was changed for the entry.
    #[serde(rename = "timePasswordChanged")]
    pub time_password_changed: String,
}

impl From<FirefoxPasswordRecord> for GenericPasswordRecord {
    fn from(value: FirefoxPasswordRecord) -> Self {
        Self {
            label: value.url.to_string(),
            url: vec![value.url],
            username: value.username,
            password: value.password,
            otp_auth: None,
            tags: None,
            note: None,
        }
    }
}

impl From<FirefoxPasswordRecord> for GenericCsvEntry {
    fn from(value: FirefoxPasswordRecord) -> Self {
        Self::Password(value.into())
    }
}

/// Parse records from a reader.
pub async fn parse_reader<R: AsyncRead + Unpin + Send>(
    reader: R,
) -> Result<Vec<FirefoxPasswordRecord>> {
    read_csv_records::<FirefoxPasswordRecord, _>(reader).await
}

/// Parse records from a path.
pub async fn parse_path<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<FirefoxPasswordRecord>> {
    parse_reader(vfs::File::open(path).await?).await
}

/// Import a Firefox passwords CSV export into a vault.
pub struct FirefoxPasswordCsv;

#[async_trait]
impl Convert for FirefoxPasswordCsv {
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
