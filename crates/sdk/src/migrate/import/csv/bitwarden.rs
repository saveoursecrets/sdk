//! Parser for the Bitwarden CSV export.
//!
//! Unlike most of the other formats this format includes notes
//! as well as passwords.

use serde::Deserialize;
use std::path::{Path, PathBuf};
use url::Url;

use crate::{crypto::AccessKey, vault::Vault};
use async_trait::async_trait;
use tokio::io::AsyncRead;

use super::{
    GenericCsvConvert, GenericCsvEntry, GenericNoteRecord,
    GenericPasswordRecord, UNTITLED,
};
use crate::migrate::{import::read_csv_records, Convert, Result};

#[cfg(not(test))]
use crate::vfs;
#[cfg(test)]
use tokio::fs as vfs;

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

        Self {
            label,
            url: value.login_uri,
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

#[cfg(test)]
mod test {
    use super::{parse_path, BitwardenCsv};
    use crate::migrate::Convert;
    use anyhow::Result;

    use crate::{
        crypto::AccessKey,
        passwd::diceware::generate_passphrase,
        storage::search::SearchIndex,
        vault::{BuilderCredentials, Gatekeeper, VaultBuilder},
    };
    use url::Url;

    #[tokio::test]
    async fn bitwarden_passwords_csv_parse() -> Result<()> {
        let mut records =
            parse_path("../../tests/fixtures/migrate/bitwarden-export.csv")
                .await?;
        assert_eq!(2, records.len());

        let first = records.remove(0);
        let second = records.remove(0);

        assert_eq!("1", &first.favorite);
        assert_eq!("Mock Login", &first.name);
        assert_eq!("Some notes about the login.", &first.notes);
        assert_eq!(Some(Url::parse("https://example.com")?), first.login_uri);
        assert_eq!("mock-user", &first.login_username);
        assert_eq!("XXX-MOCK-1", &first.login_password);

        assert_eq!("Mock Note", &second.name);
        assert_eq!("This is a mock note.", &second.notes);

        Ok(())
    }

    #[tokio::test]
    async fn bitwarden_passwords_csv_convert() -> Result<()> {
        let (passphrase, _) = generate_passphrase()?;
        let vault = VaultBuilder::new()
            .build(BuilderCredentials::Password(passphrase.clone(), None))
            .await?;

        let key: AccessKey = passphrase.into();
        let vault = BitwardenCsv
            .convert(
                "../../tests/fixtures/migrate/bitwarden-export.csv".into(),
                vault,
                &key,
            )
            .await?;

        let mut search = SearchIndex::new();
        let mut keeper = Gatekeeper::new(vault);
        keeper.unlock(&key).await?;
        search.add_folder(&keeper).await?;

        let first = search.find_by_label(keeper.id(), "Mock Login", None);
        assert!(first.is_some());

        let second = search.find_by_label(keeper.id(), "Mock Note", None);
        assert!(second.is_some());

        Ok(())
    }
}
