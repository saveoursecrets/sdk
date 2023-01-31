//! Parser for the Dashlane CSV zip export.

use secrecy::SecretString;
use serde::Deserialize;
use std::{
    fs::File,
    io::{Read, Seek},
    path::{Path, PathBuf},
};
use url::Url;

use sos_core::{secret::IdentificationKind, vault::Vault, Timestamp};

use super::{
    GenericCsvConvert, GenericCsvEntry, GenericIdRecord, GenericNoteRecord,
    GenericPasswordRecord, UNTITLED,
};
use crate::{Convert, Result};

/// Record used to deserialize dashlane CSV files.
pub enum DashlaneRecord {
    /// Password login.
    Password(DashlanePasswordRecord),
    /// Secure note.
    Note(DashlaneNoteRecord),
    /// Identification record.
    Id(DashlaneIdRecord),
}

impl From<DashlaneRecord> for GenericCsvEntry {
    fn from(value: DashlaneRecord) -> Self {
        match value {
            DashlaneRecord::Password(record) => {
                GenericCsvEntry::Password(record.into())
            }
            DashlaneRecord::Note(record) => {
                GenericCsvEntry::Note(record.into())
            }
            DashlaneRecord::Id(record) => GenericCsvEntry::Id(record.into()),
        }
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

/// Record for an entry in a Dashlane id CSV export.
#[derive(Deserialize)]
pub struct DashlaneIdRecord {
    /// The type of the entry.
    #[serde(rename = "type")]
    pub kind: String,
    /// The number for the entry.
    pub number: String,
    /// The name for the entry.
    pub name: String,
    /// The issue date for the entry.
    pub issue_date: String,
    /// The expiration date for the entry.
    pub expiration_date: String,
    /// The place of issue for the entry.
    pub place_of_issue: String,
    /// The state for the entry.
    pub state: String,
}

impl From<DashlaneIdRecord> for DashlaneRecord {
    fn from(value: DashlaneIdRecord) -> Self {
        Self::Id(value)
    }
}

impl From<DashlaneIdRecord> for GenericIdRecord {
    fn from(value: DashlaneIdRecord) -> Self {
        let label = if value.name.is_empty() {
            UNTITLED.to_owned()
        } else {
            value.name
        };

        let id_kind = match &value.kind[..] {
            "card" => IdentificationKind::IdCard,
            "passport" => IdentificationKind::Passport,
            "license" => IdentificationKind::DriverLicense,
            "social_security" => IdentificationKind::SocialSecurity,
            "tax_number" => IdentificationKind::TaxNumber,
            _ => {
                panic!("unsupported type of id {}", value.kind);
            }
        };

        let issue_place =
            if !value.state.is_empty() && !value.place_of_issue.is_empty() {
                format!("{}, {}", value.state, value.place_of_issue)
            } else {
                value.place_of_issue
            };

        let issue_place = if !issue_place.is_empty() {
            Some(issue_place)
        } else {
            None
        };

        let issue_date = if !value.issue_date.is_empty() {
            match Timestamp::parse_simple_date(&value.issue_date) {
                Ok(date) => Some(date),
                Err(_) => None,
            }
        } else {
            None
        };

        let expiration_date = if !value.expiration_date.is_empty() {
            match Timestamp::parse_simple_date(&value.expiration_date) {
                Ok(date) => Some(date),
                Err(_) => None,
            }
        } else {
            None
        };

        Self {
            label,
            id_kind,
            number: value.number,
            issue_place,
            issue_date,
            expiration_date,
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
pub fn parse_path<P: AsRef<Path>>(path: P) -> Result<Vec<DashlaneRecord>> {
    parse(File::open(path.as_ref())?)
}

fn parse<R: Read + Seek>(rdr: R) -> Result<Vec<DashlaneRecord>> {
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
                let mut rdr = csv::Reader::from_reader(file);
                for result in rdr.deserialize() {
                    let record: DashlaneIdRecord = result?;
                    records.push(record.into());
                }
            }
            "payments.csv" => {
                todo!()
            }
            "personalInfo.csv" => {
                todo!()
            }
            _ => {
                eprintln!(
                    "unsupported dashlane file encountered {}",
                    file.name()
                );
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
