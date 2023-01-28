//! Parser for the Chrome passwords CSV export.

use secrecy::SecretString;
use serde::Deserialize;
use std::{
    io::Read,
    path::{Path, PathBuf},
};
use url::Url;

use sos_core::vault::Vault;

use super::{GenericCsvConvert, GenericPasswordRecord};
use crate::{Convert, Result};

/// Record for an entry in a Chrome passwords CSV export.
#[derive(Deserialize)]
pub struct ChromePasswordRecord {
    /// The name of the entry.
    pub name: String,
    /// The URL of the entry.
    pub url: Option<Url>,
    /// The username for the entry.
    pub username: String,
    /// The password for the entry.
    pub password: String,
}

impl From<ChromePasswordRecord> for GenericPasswordRecord {
    fn from(value: ChromePasswordRecord) -> Self {
        Self {
            label: value.name,
            url: value.url,
            username: value.username,
            password: value.password,
            otp_auth: None,
            tags: None,
        }
    }
}

/// Parse records from a reader.
pub fn parse_reader<R: Read>(reader: R) -> Result<Vec<ChromePasswordRecord>> {
    parse(csv::Reader::from_reader(reader))
}

/// Parse records from a path.
pub fn parse_path<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<ChromePasswordRecord>> {
    parse(csv::Reader::from_path(path)?)
}

fn parse<R: Read>(
    mut rdr: csv::Reader<R>,
) -> Result<Vec<ChromePasswordRecord>> {
    let mut records = Vec::new();
    for result in rdr.deserialize() {
        let record: ChromePasswordRecord = result?;
        records.push(record);
    }
    Ok(records)
}

/// Import a Chrome passwords CSV export into a vault.
pub struct ChromePasswordCsv;

impl Convert for ChromePasswordCsv {
    type Input = PathBuf;

    fn convert(
        &self,
        source: Self::Input,
        vault: Vault,
        password: SecretString,
    ) -> crate::Result<Vault> {
        let records: Vec<GenericPasswordRecord> =
            parse_path(source)?.into_iter().map(|r| r.into()).collect();
        GenericCsvConvert.convert(records, vault, password)
    }
}

#[cfg(test)]
mod test {
    use super::{parse_path, ChromePasswordCsv};
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
    fn chrome_passwords_csv_parse() -> Result<()> {
        let mut records = parse_path("fixtures/chrome-export.csv")?;
        assert_eq!(2, records.len());

        let first = records.remove(0);
        let second = records.remove(0);

        assert_eq!("mock.example.com", &first.name);
        assert_eq!(
            Some(Url::parse("https://mock.example.com/login")?),
            first.url
        );
        assert_eq!("mock@example.com", &first.username);
        assert_eq!("XXX-MOCK-1", &first.password);

        assert_eq!("mock2.example.com", &second.name);
        assert_eq!(
            Some(Url::parse("https://mock2.example.com/login")?),
            second.url
        );
        assert_eq!("mock2@example.com", &second.username);
        assert_eq!("XXX-MOCK-2", &second.password);

        Ok(())
    }

    #[test]
    fn chrome_passwords_csv_convert() -> Result<()> {
        let (passphrase, _) = generate_passphrase()?;
        let mut vault: Vault = Default::default();
        vault.initialize(passphrase.expose_secret(), None)?;

        let vault = ChromePasswordCsv.convert(
            "fixtures/chrome-export.csv".into(),
            vault,
            passphrase.clone(),
        )?;

        let search_index = Arc::new(RwLock::new(SearchIndex::new()));
        let mut keeper =
            Gatekeeper::new(vault, Some(Arc::clone(&search_index)));
        keeper.unlock(passphrase.expose_secret())?;
        keeper.create_search_index()?;

        let search = search_index.read();
        let first = search.find_by_label(keeper.id(), "mock.example.com");
        assert!(first.is_some());

        let second = search.find_by_label(keeper.id(), "mock2.example.com");
        assert!(second.is_some());

        Ok(())
    }
}
