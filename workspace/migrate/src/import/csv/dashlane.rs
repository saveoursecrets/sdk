//! Parser for the Dashlane CSV zip export.

use secrecy::SecretString;
use serde::Deserialize;
use std::{
    io::{Read, Seek},
    fs::File,
    path::{Path, PathBuf},
};
use url::Url;

use sos_core::vault::Vault;

use super::{
    GenericCsvConvert, GenericCsvEntry, GenericNoteRecord, GenericPasswordRecord, UNTITLED,
};
use crate::{Convert, Result};

/// Record used to deserialize dashlane CSV files.
pub enum DashlaneRecord {
    /// Password login.
    Password(DashlanePasswordRecord),
    /// Secure note.
    Note(DashlaneNoteRecord),
}

impl From<DashlaneRecord> for GenericCsvEntry {
    fn from(value: DashlaneRecord) -> Self {
        todo!();
    }
}

/// Record for an entry in a Dashlane notes CSV export.
#[derive(Deserialize)]
pub struct DashlaneNoteRecord {
    /// The title of the entry.
    pub title: String,
    /// The note for the entry.
    pub note: String,
}

impl From<DashlaneNoteRecord> for DashlaneRecord {
    fn from(value: DashlaneNoteRecord) -> Self {
        Self::Note(value)
    }
}

impl From<DashlaneNoteRecord> for GenericNoteRecord {
    fn from(value: DashlaneNoteRecord) -> Self {
        let label = if value.title.is_empty() {
            UNTITLED.to_owned()
        } else {
            value.title
        };
        Self {
            label,
            text: value.note,
            tags: None,
        }
    }
}

/// Record for an entry in a Dashlane passwords CSV export.
#[derive(Deserialize)]
pub struct DashlanePasswordRecord {
    /// The title of the entry.
    pub title: String,
    /// The URL of the entry.
    pub url: Option<Url>,
    /// The username for the entry.
    pub username: String,
    /// The password for the entry.
    pub password: String,
    /// The note for the entry.
    pub note: String,
    /// The category for the entry.
    pub category: String,
    /// The OTP secret for the entry.
    #[serde(rename = "otpSecret")]
    pub otp_secret: String,
}

impl From<DashlanePasswordRecord> for DashlaneRecord {
    fn from(value: DashlanePasswordRecord) -> Self {
        Self::Password(value)
    }
}

impl From<DashlanePasswordRecord> for GenericPasswordRecord {
    fn from(value: DashlanePasswordRecord) -> Self {
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
            otp_auth: None,
            tags: None,
        }
    }
}

/// Parse records from a path.
pub fn parse_path<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<DashlaneRecord>> {
    parse(File::open(path.as_ref())?)
}

fn parse<R: Read + Seek>(
    rdr: R,
) -> Result<Vec<DashlaneRecord>> {
    let mut records = Vec::new();
    let mut zip = zip::ZipArchive::new(rdr)?;
    for i in 0..zip.len() {
        let file = zip.by_index(i)?;
        //println!("Filename: {}", file.name());
        match file.name() {
            "securenotes.csv" => {
                let mut rdr = csv::Reader::from_reader(file);
                for result in rdr.deserialize() {
                    let record: DashlaneNoteRecord = result?;
                    records.push(record.into());
                }
            }
            "credentials.csv" => {
                let mut rdr = csv::Reader::from_reader(file);
                for result in rdr.deserialize() {
                    let record: DashlanePasswordRecord = result?;
                    records.push(record.into());
                }
            }
            "ids.csv" => {
                todo!();
                /*
                let mut rdr = csv::Reader::from_reader(file);
                for result in rdr.deserialize() {
                    let record: DashlanePasswordRecord = result?;
                    records.push(record.into());
                }
                */
            }
            _ => {
                eprintln!(
                    "unsupported dashlane file encountered {}", file.name());
            }
        }
    }
    Ok(records)
}

/// Import a Dashlane CSV zip archive into a vault.
pub struct DashlaneCsvZip;

impl Convert for DashlaneCsvZip {
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
    use super::{parse_path, DashlaneCsvZip};
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
    fn dashlane_csv_parse() -> Result<()> {
        let mut records = parse_path("fixtures/dashlane-export.zip")?;
        assert_eq!(2, records.len());
        
        /*
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
        */

        Ok(())
    }

    /*
    #[test]
    fn dashlane_csv_convert() -> Result<()> {
        let (passphrase, _) = generate_passphrase()?;
        let mut vault: Vault = Default::default();
        vault.initialize(passphrase.expose_secret(), None)?;

        let vault = DashlanePasswordCsv.convert(
            "fixtures/dashlane-export.csv".into(),
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
    */
}
