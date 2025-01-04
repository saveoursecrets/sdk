//! Parser for the Bitwarden CSV export.
//!
//! Unlike most of the other formats this format includes notes
//! as well as passwords.

use async_trait::async_trait;
use serde::Deserialize;
use sos_core::crypto::AccessKey;
use sos_vault::Vault;
use sos_vfs as vfs;
use std::path::{Path, PathBuf};
use tokio::io::AsyncRead;
use url::Url;

use super::{
    GenericCsvConvert, GenericCsvEntry, GenericNoteRecord,
    GenericPasswordRecord, UNTITLED,
};
use crate::{import::read_csv_records, Convert, Result};

const TYPE_LOGIN: &str = "login";
const TYPE_NOTE: &str = "note";

/// Record for an entry in a Bitwarden passwords CSV export.
#[derive(Deserialize)]
pub struct BitwardenPasswordRecord {
    /// A folder name for the entry.
    pub folder: String,
    /// A favorite flag for the entry.
    pub favorite: String,
    /// The type of the entry.
    #[serde(rename = "type")]
    pub kind: String,
    /// The name of the entry.
    pub name: String,
    /// The notes for the entry.
    pub notes: String,
    /// The fields for the entry.
    pub fields: String,
    /// The reprompt for the entry.
    pub reprompt: String,
    /// The URL of the entry.
    pub login_uri: Option<Url>,
    /// The username for the entry.
    pub login_username: String,
    /// The password for the entry.
    pub login_password: String,
    /// The login TOTP for the entry.
    pub login_totp: String,
}

impl From<BitwardenPasswordRecord> for GenericPasswordRecord {
    fn from(value: BitwardenPasswordRecord) -> Self {
        let label = if value.name.is_empty() {
            UNTITLED.to_owned()
        } else {
            value.name
        };

        let note = if !value.notes.is_empty() {
            Some(value.notes)
        } else {
            None
        };

        let url = if let Some(uri) = value.login_uri {
            vec![uri]
        } else {
            vec![]
        };

        Self {
            label,
            url,
            username: value.login_username,
            password: value.login_password,
            otp_auth: None,
            tags: None,
            note,
        }
    }
}

impl From<BitwardenPasswordRecord> for GenericNoteRecord {
    fn from(value: BitwardenPasswordRecord) -> Self {
        let label = if value.name.is_empty() {
            UNTITLED.to_owned()
        } else {
            value.name
        };
        Self {
            label,
            text: value.notes,
            tags: None,
            note: None,
        }
    }
}

impl From<BitwardenPasswordRecord> for GenericCsvEntry {
    fn from(value: BitwardenPasswordRecord) -> Self {
        if value.kind == TYPE_LOGIN {
            Self::Password(value.into())
        } else {
            Self::Note(value.into())
        }
    }
}

/// Parse records from a reader.
pub async fn parse_reader<R: AsyncRead + Unpin + Send>(
    reader: R,
) -> Result<Vec<BitwardenPasswordRecord>> {
    read_csv_records::<BitwardenPasswordRecord, _>(reader).await
}

/// Parse records from a path.
pub async fn parse_path<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<BitwardenPasswordRecord>> {
    parse_reader(vfs::File::open(path).await?).await
}

/// Import a Bitwarden passwords CSV export into a vault.
pub struct BitwardenCsv;

#[async_trait]
impl Convert for BitwardenCsv {
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
            .filter(|record| {
                record.kind == TYPE_LOGIN || record.kind == TYPE_NOTE
            })
            .map(|r| r.into())
            .collect();
        GenericCsvConvert.convert(records, vault, key).await
    }
}
