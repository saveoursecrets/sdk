//! Parser for the 1Password passwords CSV export.

use serde::{
    de::{self, Deserializer, Unexpected, Visitor},
    Deserialize,
};
use std::{
    collections::HashSet,
    fmt,
    path::{Path, PathBuf},
};
use url::Url;

use async_trait::async_trait;
use sos_sdk::{crypto::AccessKey, vault::Vault, vfs};
use tokio::io::AsyncRead;

use super::{
    GenericCsvConvert, GenericCsvEntry, GenericPasswordRecord, UNTITLED,
};
use crate::{import::read_csv_records, Convert, Result};

/// Record for an entry in a MacOS passwords CSV export.
#[derive(Deserialize)]
pub struct OnePasswordRecord {
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
    /// OTP auth information for the entry.
    #[serde(rename = "OTPAuth")]
    pub otp_auth: Option<String>,
    /// Flag if the entry is a favorite.
    #[serde(rename = "Favorite", deserialize_with = "deserialize_bool")]
    pub favorite: bool,
    /// Flag if the entry is archived.
    #[serde(rename = "Archived", deserialize_with = "deserialize_bool")]
    pub archived: bool,
    /// Collection of tags, delimited by a semi-colon.
    #[serde(rename = "Tags")]
    pub tags: String,
    /// Notes for the entry.
    #[serde(rename = "Notes")]
    pub notes: String,
}

impl From<OnePasswordRecord> for GenericPasswordRecord {
    fn from(value: OnePasswordRecord) -> Self {
        let tags: Option<HashSet<String>> = if !value.tags.is_empty() {
            Some(value.tags.split(';').map(|s| s.trim().to_owned()).collect())
        } else {
            None
        };

        let label = if value.title.is_empty() {
            UNTITLED.to_owned()
        } else {
            value.title
        };

        let note = if !value.notes.is_empty() {
            Some(value.notes)
        } else {
            None
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
            tags,
            note,
        }
    }
}

impl From<OnePasswordRecord> for GenericCsvEntry {
    fn from(value: OnePasswordRecord) -> Self {
        Self::Password(value.into())
    }
}

/// Parse records from a reader.
pub async fn parse_reader<R: AsyncRead + Unpin + Send>(
    reader: R,
) -> Result<Vec<OnePasswordRecord>> {
    read_csv_records::<OnePasswordRecord, _>(reader).await
}

/// Parse records from a path.
pub async fn parse_path<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<OnePasswordRecord>> {
    parse_reader(vfs::File::open(path).await?).await
}

/// Import a MacOS passwords CSV export into a vault.
pub struct OnePasswordCsv;

#[async_trait]
impl Convert for OnePasswordCsv {
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

struct BoolString;

impl<'de> Visitor<'de> for BoolString {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a string representing a boolean flag")
    }

    fn visit_str<E>(self, s: &str) -> std::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        let b = s.to_lowercase();
        if b == "true" || b == "false" {
            Ok(s.to_owned())
        } else {
            Err(de::Error::invalid_value(Unexpected::Str(s), &self))
        }
    }
}

fn deserialize_bool<'de, D>(
    deserializer: D,
) -> std::result::Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let value = deserializer.deserialize_str(BoolString)?;
    Ok(value.to_lowercase() == "true")
}
