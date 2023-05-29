//! Parser for the 1Password passwords CSV export.

use secrecy::SecretString;
use serde::{
    de::{self, Deserializer, Unexpected, Visitor},
    Deserialize,
};
use std::{
    collections::HashSet,
    fmt,
    io::Read,
    path::{Path, PathBuf},
};
use url::Url;

use async_trait::async_trait;
use sos_sdk::vault::Vault;

use super::{
    GenericCsvConvert, GenericCsvEntry, GenericPasswordRecord, UNTITLED,
};
use crate::{Convert, Result};

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

        Self {
            label,
            url: value.url,
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
pub fn parse_reader<R: Read>(reader: R) -> Result<Vec<OnePasswordRecord>> {
    parse(csv::Reader::from_reader(reader))
}

/// Parse records from a path.
pub fn parse_path<P: AsRef<Path>>(path: P) -> Result<Vec<OnePasswordRecord>> {
    parse(csv::Reader::from_path(path)?)
}

fn parse<R: Read>(mut rdr: csv::Reader<R>) -> Result<Vec<OnePasswordRecord>> {
    let mut records = Vec::new();
    for result in rdr.deserialize() {
        let record: OnePasswordRecord = result?;
        records.push(record);
    }
    Ok(records)
}

/// Import a MacOS passwords CSV export into a vault.
pub struct OnePasswordCsv;

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Convert for OnePasswordCsv {
    type Input = PathBuf;

    async fn convert(
        &self,
        source: Self::Input,
        vault: Vault,
        password: SecretString,
    ) -> crate::Result<Vault> {
        let records: Vec<GenericCsvEntry> =
            parse_path(source)?.into_iter().map(|r| r.into()).collect();
        GenericCsvConvert.convert(records, vault, password).await
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

#[cfg(test)]
mod test {
    use super::{super::UNTITLED, parse_path, OnePasswordCsv};
    use crate::Convert;
    use anyhow::Result;
    use parking_lot::RwLock;

    use sos_sdk::{
        passwd::diceware::generate_passphrase,
        search::SearchIndex,
        vault::{Gatekeeper, Vault},
    };
    use std::sync::Arc;
    use url::Url;

    #[test]
    fn one_password_csv_parse() -> Result<()> {
        let mut records = parse_path("fixtures/1password-export.csv")?;
        assert_eq!(6, records.len());

        let first = records.remove(0);
        assert_eq!("Password (No Username)", first.title);
        assert_eq!(None, first.url);
        assert_eq!("", first.username,);
        assert_eq!("XXX-MOCK-1", first.password);
        assert_eq!("", first.tags);
        assert_eq!("", first.notes);
        assert!(!first.archived);
        assert!(!first.favorite);

        let second = records.remove(0);
        assert_eq!("Mock Archive Password", second.title);
        assert_eq!(Some(Url::parse("https://example.com")?), second.url);
        assert_eq!("mock-user", second.username,);
        assert_eq!("XXX-MOCK-2", second.password);
        assert_eq!("mock;passwords", second.tags);
        assert_eq!(
            "Mock notes about the mock password that was moved to the archive.",
            second.notes
        );
        assert!(second.archived);
        assert!(!second.favorite);

        let third = records.remove(0);
        assert_eq!("", third.title);
        assert_eq!(None, third.url);
        assert_eq!("", third.username,);
        assert_eq!("", third.password);
        assert_eq!("", third.tags);
        assert_eq!("", third.notes);
        assert!(!third.archived);
        assert!(!third.favorite);

        let fourth = records.remove(0);
        assert_eq!("Mock Favorite Password", fourth.title);
        assert_eq!(None, fourth.url);
        assert_eq!("mock-user", fourth.username,);
        assert_eq!("XXX-MOCK-3", fourth.password);
        assert_eq!("mock", fourth.tags);
        assert_eq!("", fourth.notes);
        assert!(!fourth.archived);
        assert!(fourth.favorite);

        let fifth = records.remove(0);
        assert_eq!("Password (No Password)", fifth.title);
        assert_eq!(None, fifth.url);
        assert_eq!("mock-user", fifth.username,);
        assert_eq!("", fifth.password);
        assert_eq!("", fifth.tags);
        assert_eq!("", fifth.notes);
        assert!(!fifth.archived);
        assert!(!fifth.favorite);

        let sixth = records.remove(0);
        assert_eq!("Password (No username or password)", sixth.title);
        assert_eq!(None, sixth.url);
        assert_eq!("", sixth.username,);
        assert_eq!("", sixth.password);
        assert_eq!("", sixth.tags);
        assert_eq!("", sixth.notes);
        assert!(!sixth.archived);
        assert!(!sixth.favorite);

        Ok(())
    }

    #[tokio::test]
    async fn one_password_csv_convert() -> Result<()> {
        let (passphrase, _) = generate_passphrase()?;
        let mut vault: Vault = Default::default();
        vault.initialize(passphrase.clone(), None)?;

        let vault = OnePasswordCsv
            .convert(
                "fixtures/1password-export.csv".into(),
                vault,
                passphrase.clone(),
            )
            .await?;

        let search_index = Arc::new(RwLock::new(SearchIndex::new()));
        let mut keeper =
            Gatekeeper::new(vault, Some(Arc::clone(&search_index)));
        keeper.unlock(passphrase)?;
        keeper.create_search_index()?;

        let search = search_index.read();
        assert_eq!(6, search.len());

        let search = search_index.read();
        let untitled = search.find_by_label(keeper.id(), UNTITLED, None);
        assert!(untitled.is_some());

        Ok(())
    }
}
