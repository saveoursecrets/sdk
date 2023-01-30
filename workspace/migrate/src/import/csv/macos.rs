//! Parser for the MacOS passwords CSV export.

use secrecy::SecretString;
use serde::Deserialize;
use std::{
    io::Read,
    path::{Path, PathBuf},
};
use url::Url;

use sos_core::vault::Vault;

use super::{GenericCsvConvert, GenericCsvEntry, GenericPasswordRecord, UNTITLED};
use crate::{Convert, Result};

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
        Self {
            label,
            url: value.url,
            username: value.username,
            password: value.password,
            otp_auth: value.otp_auth,
            tags: None,
        }
    }
}

impl From<MacPasswordRecord> for GenericCsvEntry {
    fn from(value: MacPasswordRecord) -> Self {
        Self::Password(value.into())
    }
}

/// Parse records from a reader.
pub fn parse_reader<R: Read>(reader: R) -> Result<Vec<MacPasswordRecord>> {
    parse(csv::Reader::from_reader(reader))
}

/// Parse records from a path.
pub fn parse_path<P: AsRef<Path>>(path: P) -> Result<Vec<MacPasswordRecord>> {
    parse(csv::Reader::from_path(path)?)
}

fn parse<R: Read>(mut rdr: csv::Reader<R>) -> Result<Vec<MacPasswordRecord>> {
    let mut records = Vec::new();
    for result in rdr.deserialize() {
        let record: MacPasswordRecord = result?;
        records.push(record);
    }
    Ok(records)
}

/// Import a MacOS passwords CSV export into a vault.
pub struct MacPasswordCsv;

impl Convert for MacPasswordCsv {
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
    use super::{parse_path, MacPasswordCsv};
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
    fn macos_passwords_csv_parse() -> Result<()> {
        let mut records = parse_path("fixtures/macos-export.csv")?;
        assert_eq!(2, records.len());

        let first = records.remove(0);
        let second = records.remove(0);

        assert_eq!("mock.example.com (mock@example.com)", &first.title);
        assert_eq!(Some(Url::parse("https://mock.example.com/")?), first.url);
        assert_eq!("mock@example.com", &first.username);
        assert_eq!("XXX-MOCK-1", &first.password);
        assert!(first.otp_auth.is_none());

        assert_eq!("mock2.example.com (mock-username)", &second.title);
        assert_eq!(
            Some(Url::parse("https://mock2.example.com/")?),
            second.url
        );
        assert_eq!("mock-username", &second.username);
        assert_eq!("XXX-MOCK-2", &second.password);
        assert!(second.otp_auth.is_none());

        Ok(())
    }

    #[test]
    fn macos_passwords_csv_convert() -> Result<()> {
        let (passphrase, _) = generate_passphrase()?;
        let mut vault: Vault = Default::default();
        vault.initialize(passphrase.expose_secret(), None)?;

        let vault = MacPasswordCsv.convert(
            "fixtures/macos-export.csv".into(),
            vault,
            passphrase.clone(),
        )?;

        let search_index = Arc::new(RwLock::new(SearchIndex::new()));
        let mut keeper =
            Gatekeeper::new(vault, Some(Arc::clone(&search_index)));
        keeper.unlock(passphrase.expose_secret())?;
        keeper.create_search_index()?;

        let search = search_index.read();
        let first = search.find_by_label(
            keeper.id(),
            "mock.example.com (mock@example.com)",
        );
        assert!(first.is_some());

        let second = search
            .find_by_label(keeper.id(), "mock2.example.com (mock-username)");
        assert!(second.is_some());

        Ok(())
    }
}
