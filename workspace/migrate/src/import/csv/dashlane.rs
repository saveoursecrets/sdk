//! Parser for the Dashlane CSV zip export.

use async_trait::async_trait;

use serde::Deserialize;
use sos_sdk::{
    crypto::AccessKey,
    vault::{secret::IdentityKind, Vault},
    vfs::File,
    Timestamp,
};
use std::{
    collections::HashSet,
    io::Cursor,
    path::{Path, PathBuf},
};
use time::{Date, Month};
use url::Url;
use vcard4::{property::DeliveryAddress, uriparse::URI as Uri, VcardBuilder};

use async_zip::tokio::read::seek::ZipFileReader;
use tokio::io::{AsyncRead, AsyncSeek};

use super::{
    GenericContactRecord, GenericCsvConvert, GenericCsvEntry,
    GenericIdRecord, GenericNoteRecord, GenericPasswordRecord,
    GenericPaymentRecord, UNTITLED,
};
use crate::{import::read_csv_records, Convert, Result};

/// Record used to deserialize dashlane CSV files.
#[derive(Debug)]
pub enum DashlaneRecord {
    /// Password login.
    Password(DashlanePasswordRecord),
    /// Secure note.
    Note(DashlaneNoteRecord),
    /// Identity record.
    Id(DashlaneIdRecord),
    /// Payment record.
    Payment(DashlanePaymentRecord),
    /// Contact record.
    Contact(DashlaneContactRecord),
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
            DashlaneRecord::Payment(record) => {
                GenericCsvEntry::Payment(record.into())
            }
            DashlaneRecord::Contact(record) => {
                GenericCsvEntry::Contact(Box::new(record.into()))
            }
        }
    }
}

/// Record for an entry in a Dashlane notes CSV export.
#[derive(Debug, Deserialize)]
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
            note: None,
        }
    }
}

/// Record for an entry in a Dashlane id CSV export.
#[derive(Debug, Deserialize)]
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
            "card" => IdentityKind::IdCard,
            "passport" => IdentityKind::Passport,
            "license" => IdentityKind::DriverLicense,
            "social_security" => IdentityKind::SocialSecurity,
            "tax_number" => IdentityKind::TaxNumber,
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
            note: None,
        }
    }
}

/// Record for an entry in a Dashlane id CSV export.
#[derive(Debug, Deserialize)]
pub struct DashlanePaymentRecord {
    /// The type of the entry.
    #[serde(rename = "type")]
    pub kind: String,
    /// The account name for the entry.
    pub account_name: String,
    /// The account holder for the entry.
    pub account_holder: String,
    /// The account number for the entry.
    pub account_number: String,
    /// The routing number for the entry.
    pub routing_number: String,
    /// The CC number for the entry.
    pub cc_number: String,
    /// The CVV code for the entry.
    pub code: String,
    /// The expiration month for the entry.
    pub expiration_month: String,
    /// The expiration year for the entry.
    pub expiration_year: String,
    /// The country for the entry.
    pub country: String,
    /// The note for the entry.
    pub note: String,
}

impl From<DashlanePaymentRecord> for DashlaneRecord {
    fn from(value: DashlanePaymentRecord) -> Self {
        Self::Payment(value)
    }
}

impl From<DashlanePaymentRecord> for GenericPaymentRecord {
    fn from(value: DashlanePaymentRecord) -> Self {
        let label = if value.account_name.is_empty() {
            UNTITLED.to_owned()
        } else {
            value.account_name
        };

        let expiration = if let (Ok(month), Ok(year)) = (
            value.expiration_month.parse::<u8>(),
            value.expiration_year.parse::<i32>(),
        ) {
            if let Ok(month) = Month::try_from(month) {
                Timestamp::from_calendar_date(year, month, 1).ok()
            } else {
                None
            }
        } else {
            None
        };

        let note = if !value.note.is_empty() {
            Some(value.note)
        } else {
            None
        };

        match &value.kind[..] {
            "bank" => GenericPaymentRecord::BankAccount {
                label,
                account_holder: value.account_holder,
                account_number: value.account_number,
                routing_number: value.routing_number,
                country: value.country,
                note,
                tags: None,
            },
            "payment_card" => GenericPaymentRecord::Card {
                label,
                number: value.cc_number,
                code: value.code,
                expiration,
                country: value.country,
                note,
                tags: None,
            },
            _ => panic!("unexpected payment type {}", value.kind),
        }
    }
}

/// Record for an entry in a Dashlane passwords CSV export.
#[derive(Debug, Deserialize)]
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

        let tags = if !value.category.is_empty() {
            let mut tags = HashSet::new();
            tags.insert(value.category);
            Some(tags)
        } else {
            None
        };

        let note = if !value.note.is_empty() {
            Some(value.note)
        } else {
            None
        };

        Self {
            label,
            url: value.url,
            username: value.username,
            password: value.password,
            otp_auth: None,
            tags,
            note,
        }
    }
}

/// Record for an entry in a Dashlane personalInfo CSV export.
///
/// Fields that are currently not handled:
///
/// * login
/// * place_of_birth
/// * email_type
/// * address_door_code
///
#[derive(Debug, Deserialize)]
pub struct DashlaneContactRecord {
    /// The item name of the entry.
    pub item_name: String,
    /// The title.
    pub title: String,
    /// The first name.
    pub first_name: String,
    /// The middle name.
    pub middle_name: String,
    /// The last name.
    pub last_name: String,

    /// The address.
    pub address: String,
    /// The city.
    pub city: String,
    /// The state.
    pub state: String,
    /// The country.
    pub country: String,
    /// The postal code.
    pub zip: String,

    /// Address recipient.
    pub address_recipient: String,
    /// Address apartment.
    pub address_apartment: String,
    /// Address floor.
    pub address_floor: String,
    /// Address building.
    pub address_building: String,

    /// The phone number.
    pub phone_number: String,
    /// An email address.
    pub email: String,
    /// A website URL.
    pub url: String,

    /// A date of birth.
    pub date_of_birth: String,

    /// A job title.
    pub job_title: String,
}

impl From<DashlaneContactRecord> for DashlaneRecord {
    fn from(value: DashlaneContactRecord) -> Self {
        Self::Contact(value)
    }
}

impl From<DashlaneContactRecord> for GenericContactRecord {
    fn from(value: DashlaneContactRecord) -> Self {
        let has_some_name_parts = !value.last_name.is_empty()
            || !value.first_name.is_empty()
            || !value.middle_name.is_empty()
            || !value.title.is_empty();

        let name: [String; 5] = [
            value.last_name.clone(),
            value.first_name.clone(),
            value.middle_name.clone(),
            value.title.clone(),
            String::new(),
        ];

        let formatted_name = if has_some_name_parts {
            let mut parts: Vec<String> = Vec::new();
            if !value.title.is_empty() {
                parts.push(value.title);
            }
            if !value.first_name.is_empty() {
                parts.push(value.first_name);
            }
            if !value.middle_name.is_empty() {
                parts.push(value.middle_name);
            }
            if !value.last_name.is_empty() {
                parts.push(value.last_name);
            }
            parts.join(" ")
        } else if !value.item_name.is_empty() {
            value.item_name.clone()
        } else {
            UNTITLED.to_owned()
        };

        let label = if value.item_name.is_empty() {
            formatted_name.clone()
        } else if !value.item_name.is_empty() {
            value.item_name
        } else {
            UNTITLED.to_owned()
        };

        let date_of_birth: Option<Date> = if !value.date_of_birth.is_empty() {
            if let Ok(date_time) =
                Timestamp::parse_simple_date(&value.date_of_birth)
            {
                Some(date_time.into_date())
            } else {
                None
            }
        } else {
            None
        };

        let url: Option<Uri<'static>> = if !value.url.is_empty() {
            Uri::try_from(&value.url[..]).ok().map(|u| u.into_owned())
        } else {
            None
        };

        let extended_address = vec![
            value.address_recipient,
            value.address_apartment,
            value.address_floor,
            value.address_building,
        ];

        let has_some_address_parts = !value.address.is_empty()
            || !value.city.is_empty()
            || !value.state.is_empty()
            || !value.zip.is_empty()
            || !value.country.is_empty();

        let address = if has_some_address_parts {
            Some(DeliveryAddress {
                po_box: None,
                extended_address: if !extended_address.is_empty() {
                    Some(extended_address.join(","))
                } else {
                    None
                },
                street_address: if !value.address.is_empty() {
                    Some(value.address)
                } else {
                    None
                },
                locality: if !value.city.is_empty() {
                    Some(value.city)
                } else {
                    None
                },
                region: if !value.state.is_empty() {
                    Some(value.state)
                } else {
                    None
                },
                country_name: if !value.country.is_empty() {
                    Some(value.country)
                } else {
                    None
                },
                postal_code: if !value.zip.is_empty() {
                    Some(value.zip)
                } else {
                    None
                },
            })
        } else {
            None
        };

        let mut builder = VcardBuilder::new(formatted_name);
        if has_some_name_parts {
            builder = builder.name(name);
        }
        if let Some(address) = address {
            builder = builder.address(address);
        }
        if !value.phone_number.is_empty() {
            builder = builder.telephone(value.phone_number);
        }
        if !value.email.is_empty() {
            builder = builder.email(value.email);
        }
        if let Some(url) = url {
            builder = builder.url(url);
        }
        if !value.job_title.is_empty() {
            builder = builder.title(value.job_title);
        }
        if let Some(date) = date_of_birth {
            builder = builder.birthday(date);
        }
        let vcard = builder.finish();
        Self {
            label,
            vcard,
            tags: None,
            note: None,
        }
    }
}

/// Parse records from a path.
pub async fn parse_path<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<DashlaneRecord>> {
    parse(File::open(path.as_ref()).await?).await
}

async fn read_entry<R: AsyncRead + AsyncSeek + Unpin>(
    zip: &mut ZipFileReader<R>,
    index: usize,
) -> Result<Vec<u8>> {
    let mut reader = zip.reader_with_entry(index).await?;
    let mut buffer = Vec::new();
    reader.read_to_end_checked(&mut buffer).await?;
    Ok(buffer)
}

async fn parse<R: AsyncRead + AsyncSeek + Unpin>(
    rdr: R,
) -> Result<Vec<DashlaneRecord>> {
    let mut records = Vec::new();
    let mut zip = ZipFileReader::with_tokio(rdr).await?;

    for index in 0..zip.file().entries().len() {
        let entry = zip.file().entries().get(index).unwrap();
        let file_name = entry.entry().filename();
        let file_name = file_name.as_str()?;

        match file_name {
            "securenotes.csv" => {
                let mut buffer = read_entry(&mut zip, index).await?;
                let reader = Cursor::new(&mut buffer);
                let mut items: Vec<DashlaneRecord> =
                    read_csv_records::<DashlaneNoteRecord, _>(reader)
                        .await?
                        .into_iter()
                        .map(|r| r.into())
                        .collect();
                records.append(&mut items);
            }
            "credentials.csv" => {
                let mut buffer = read_entry(&mut zip, index).await?;
                let reader = Cursor::new(&mut buffer);
                let mut items: Vec<DashlaneRecord> =
                    read_csv_records::<DashlanePasswordRecord, _>(reader)
                        .await?
                        .into_iter()
                        .map(|r| r.into())
                        .collect();
                records.append(&mut items);
            }
            "ids.csv" => {
                let mut buffer = read_entry(&mut zip, index).await?;
                let reader = Cursor::new(&mut buffer);
                let mut items: Vec<DashlaneRecord> =
                    read_csv_records::<DashlaneIdRecord, _>(reader)
                        .await?
                        .into_iter()
                        .map(|r| r.into())
                        .collect();
                records.append(&mut items);
            }
            "payments.csv" => {
                let mut buffer = read_entry(&mut zip, index).await?;
                let reader = Cursor::new(&mut buffer);
                let mut items: Vec<DashlaneRecord> =
                    read_csv_records::<DashlanePaymentRecord, _>(reader)
                        .await?
                        .into_iter()
                        .map(|r| r.into())
                        .collect();
                records.append(&mut items);
            }
            "personalInfo.csv" => {
                let mut buffer = read_entry(&mut zip, index).await?;
                let reader = Cursor::new(&mut buffer);
                let mut items: Vec<DashlaneRecord> =
                    read_csv_records::<DashlaneContactRecord, _>(reader)
                        .await?
                        .into_iter()
                        .map(|r| r.into())
                        .collect();
                records.append(&mut items);
            }
            _ => {
                eprintln!(
                    "unsupported dashlane file encountered {}",
                    file_name
                );
            }
        }
    }
    Ok(records)
}

/// Import a Dashlane CSV zip archive into a vault.
pub struct DashlaneCsvZip;

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Convert for DashlaneCsvZip {
    type Input = PathBuf;

    async fn convert(
        &self,
        source: Self::Input,
        vault: Vault,
        key: AccessKey,
    ) -> crate::Result<Vault> {
        let records: Vec<GenericCsvEntry> = parse_path(source)
            .await?
            .into_iter()
            .map(|r| r.into())
            .collect();
        GenericCsvConvert.convert(records, vault, key).await
    }
}

#[cfg(test)]
mod test {
    use super::{parse_path, DashlaneCsvZip, DashlaneRecord};
    use crate::Convert;
    use anyhow::Result;

    use sos_sdk::{
        account::search::SearchIndex,
        passwd::diceware::generate_passphrase,
        vault::{secret::Secret, Gatekeeper, VaultBuilder},
    };
    use url::Url;

    #[tokio::test]
    async fn dashlane_csv_parse() -> Result<()> {
        let mut records = parse_path("fixtures/dashlane-export.zip").await?;
        assert_eq!(15, records.len());

        let first = records.remove(0);
        if let DashlaneRecord::Password(record) = first {
            assert_eq!("example.com", &record.title);
            assert_eq!("mock-user", &record.username);
            assert_eq!("MOCK-1", &record.password);
            assert_eq!(Some(Url::parse("https://example.com")?), record.url);
            assert_eq!("Entertainment", &record.category);
            assert_eq!("Some notes about the login.", &record.note);
        } else {
            panic!("expecting a password record");
        }

        Ok(())
    }

    #[tokio::test]
    async fn dashlane_csv_convert() -> Result<()> {
        let (passphrase, _) = generate_passphrase()?;
        let vault = VaultBuilder::new()
            .password(passphrase.clone(), None)
            .await?;

        let vault = DashlaneCsvZip
            .convert(
                "fixtures/dashlane-export.zip".into(),
                vault,
                passphrase.clone().into(),
            )
            .await?;

        let mut search = SearchIndex::new();
        let mut keeper = Gatekeeper::new(vault);
        keeper.unlock(passphrase.into()).await?;
        search.add_folder(&keeper).await?;

        assert_eq!(15, search.len());

        let password = search.find_by_label(keeper.id(), "example.com", None);
        assert!(password.is_some());

        let id = search.find_by_label(keeper.id(), "Mock Passport", None);
        assert!(id.is_some());

        let payment = search.find_by_label(keeper.id(), "Bank account", None);
        assert!(payment.is_some());

        let contact = search.find_by_label(keeper.id(), "Mock Email", None);
        assert!(contact.is_some());

        let note = search.find_by_label(keeper.id(), "Mock note", None);
        assert!(note.is_some());

        let card =
            search.find_by_label(keeper.id(), "Mock Payment Card User", None);
        assert!(card.is_some());

        if let Some((_, secret, _)) =
            keeper.read(card.as_ref().unwrap().id()).await?
        {
            if let Secret::Card { expiry, .. } = &secret {
                //println!("{:#?}", expiry);
                assert!(expiry.is_some());
            } else {
                panic!("secret is of the wrong type {:#?}", secret);
            }
        } else {
            panic!("secret not found");
        }

        Ok(())
    }
}
