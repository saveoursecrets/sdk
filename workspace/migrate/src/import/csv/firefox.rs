//! Parser for the Firefox passwords CSV export.

use secrecy::SecretString;
use serde::Deserialize;
use std::{
    io::Read,
    path::{Path, PathBuf},
};
use url::Url;

use sos_core::vault::Vault;

use super::{GenericCsvConvert, GenericCsvEntry, GenericPasswordRecord};
use crate::{Convert, Result};

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
            url: Some(value.url),
            username: value.username,
            password: value.password,
            otp_auth: None,
            tags: None,
        }
    }
}

impl From<FirefoxPasswordRecord> for GenericCsvEntry {
    fn from(value: FirefoxPasswordRecord) -> Self {
        Self::Password(value.into())
    }
}

/// Parse records from a reader.
pub fn parse_reader<R: Read>(
    reader: R,
) -> Result<Vec<FirefoxPasswordRecord>> {
    parse(csv::Reader::from_reader(reader))
}

/// Parse records from a path.
pub fn parse_path<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<FirefoxPasswordRecord>> {
    parse(csv::Reader::from_path(path)?)
}

fn parse<R: Read>(
    mut rdr: csv::Reader<R>,
) -> Result<Vec<FirefoxPasswordRecord>> {
    let mut records = Vec::new();
    for result in rdr.deserialize() {
        let record: FirefoxPasswordRecord = result?;
        records.push(record);
    }
    Ok(records)
}

/// Import a Firefox passwords CSV export into a vault.
pub struct FirefoxPasswordCsv;

impl Convert for FirefoxPasswordCsv {
    type Input = PathBuf;

    fn convert(
        &self,
        source: Self::Input,
        vault: Vault,
        password: SecretString,
    ) -> crate::Result<Vault> {
        let records: Vec<GenericCsvEntry> =
            parse_path(source)?.into_iter().map(|r| r.into()).collect();
        GenericCsvConvert.convert(records, vault, password)
    }
}

#[cfg(test)]
mod test {
    use super::{parse_path, FirefoxPasswordCsv};
    use crate::Convert;
    use anyhow::Result;
    use parking_lot::RwLock;
    use secrecy::ExposeSecret;
    use sos_core::{
        generate_passphrase, search::SearchIndex, vault::Vault, Gatekeeper,
    };
    use std::sync::Arc;
    use url::Url;

    #[test]
    fn firefox_passwords_csv_parse() -> Result<()> {
        let mut records = parse_path("fixtures/firefox-export.csv")?;
        assert_eq!(2, records.len());

        let first = records.remove(0);
        let second = records.remove(0);

        assert_eq!(Url::parse("https://mock.example.com")?, first.url);
        assert_eq!("", &first.username);
        assert_eq!("XXX-MOCK-1", &first.password);

        assert_eq!(Url::parse("https://mock2.example.com")?, second.url);
        assert_eq!("mock-user-1", &second.username);
        assert_eq!("XXX-MOCK-2", &second.password);

        Ok(())
    }

    #[test]
    fn firefox_passwords_csv_convert() -> Result<()> {
        let (passphrase, _) = generate_passphrase()?;
        let mut vault: Vault = Default::default();
        vault.initialize(passphrase.expose_secret(), None)?;

        let vault = FirefoxPasswordCsv.convert(
            "fixtures/firefox-export.csv".into(),
            vault,
            passphrase.clone(),
        )?;

        let search_index = Arc::new(RwLock::new(SearchIndex::new()));
        let mut keeper =
            Gatekeeper::new(vault, Some(Arc::clone(&search_index)));
        keeper.unlock(passphrase.expose_secret())?;
        keeper.create_search_index()?;

        let search = search_index.read();
        let first =
            search.find_by_label(keeper.id(), "https://mock.example.com/");
        assert!(first.is_some());

        let second =
            search.find_by_label(keeper.id(), "https://mock2.example.com/");
        assert!(second.is_some());

        Ok(())
    }
}
