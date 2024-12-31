//! Parser for the Chrome passwords CSV export.

use serde::Deserialize;
use std::path::{Path, PathBuf};
use url::Url;

use async_trait::async_trait;
use sos_sdk::{crypto::AccessKey, vault::Vault, vfs};
use tokio::io::AsyncRead;

use super::{
    GenericCsvConvert, GenericCsvEntry, GenericPasswordRecord, UNTITLED,
};
use crate::{import::read_csv_records, Convert, Result};

/// Record for an entry in a Chrome passwords CSV export.
#[derive(Deserialize)]
pub struct ChromePasswordRecord {
    /// The name of the entry.
    pub name: String,
    /// The URL of the entry.
    pub url: Option<String>,
    /// The username for the entry.
    pub username: String,
    /// The password for the entry.
    pub password: String,
    /// The note for the entry.
    pub note: Option<String>,
}

impl From<ChromePasswordRecord> for GenericPasswordRecord {
    fn from(value: ChromePasswordRecord) -> Self {
        let label = if value.name.is_empty() {
            UNTITLED.to_owned()
        } else {
            value.name
        };

        let url = if let Some(url) = value.url {
            let mut websites = Vec::new();
            for u in url.split(",") {
                if let Ok(url) = u.trim().parse::<Url>() {
                    websites.push(url);
                }
            }
            websites
        } else {
            vec![]
        };

        Self {
            label,
            url,
            username: value.username,
            password: value.password,
            otp_auth: None,
            tags: None,
            note: value.note,
        }
    }
}

impl From<ChromePasswordRecord> for GenericCsvEntry {
    fn from(value: ChromePasswordRecord) -> Self {
        Self::Password(value.into())
    }
}

/// Parse records from a reader.
pub async fn parse_reader<R: AsyncRead + Unpin + Send>(
    reader: R,
) -> Result<Vec<ChromePasswordRecord>> {
    read_csv_records::<ChromePasswordRecord, _>(reader).await
}

/// Parse records from a path.
pub async fn parse_path<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<ChromePasswordRecord>> {
    parse_reader(vfs::File::open(path).await?).await
}

/// Import a Chrome passwords CSV export into a vault.
pub struct ChromePasswordCsv;

#[async_trait]
impl Convert for ChromePasswordCsv {
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

#[cfg(test)]
mod test {
    use super::{parse_path, ChromePasswordCsv};
    use crate::{import::csv::GenericPasswordRecord, Convert};
    use anyhow::Result;

    use sos_sdk::{
        crypto::AccessKey,
        passwd::diceware::generate_passphrase,
        search::SearchIndex,
        vault::{BuilderCredentials, Gatekeeper, VaultBuilder},
    };
    use url::Url;

    #[tokio::test]
    async fn chrome_passwords_csv_parse() -> Result<()> {
        let mut records =
            parse_path("../../fixtures/migrate/chrome-export.csv").await?;
        assert_eq!(2, records.len());

        let first = records.remove(0);
        let second = records.remove(0);

        assert_eq!("mock.example.com", &first.name);
        assert_eq!(
            Some("https://mock.example.com/login,https://mock.example.com/login2".to_owned()),
            first.url
        );
        assert_eq!("mock@example.com", &first.username);
        assert_eq!("XXX-MOCK-1", &first.password);

        assert_eq!("mock2.example.com", &second.name);
        assert_eq!(
            Some("https://mock2.example.com/login".to_owned()),
            second.url
        );
        assert_eq!("mock2@example.com", &second.username);
        assert_eq!("XXX-MOCK-2", &second.password);

        // Check multiple URL parsing
        let entry: GenericPasswordRecord = first.into();
        assert_eq!(
            vec![
                Url::parse("https://mock.example.com/login")?,
                Url::parse("https://mock.example.com/login2")?,
            ],
            entry.url
        );

        Ok(())
    }

    #[tokio::test]
    async fn chrome_passwords_csv_convert() -> Result<()> {
        let (passphrase, _) = generate_passphrase()?;
        let vault = VaultBuilder::new()
            .build(BuilderCredentials::Password(passphrase.clone(), None))
            .await?;

        let key: AccessKey = passphrase.into();
        let vault = ChromePasswordCsv
            .convert(
                "../../fixtures/migrate/chrome-export.csv".into(),
                vault,
                &key,
            )
            .await?;

        let mut search = SearchIndex::new();
        let mut keeper = Gatekeeper::new(vault);
        keeper.unlock(&key).await?;
        search.add_folder(&keeper).await?;

        let first =
            search.find_by_label(keeper.id(), "mock.example.com", None);
        assert!(first.is_some());

        let second =
            search.find_by_label(keeper.id(), "mock2.example.com", None);
        assert!(second.is_some());

        Ok(())
    }

    #[tokio::test]
    async fn chrome_passwords_note_csv_convert() -> Result<()> {
        let (passphrase, _) = generate_passphrase()?;
        let vault = VaultBuilder::new()
            .build(BuilderCredentials::Password(passphrase.clone(), None))
            .await?;

        let key: AccessKey = passphrase.into();
        let vault = ChromePasswordCsv
            .convert(
                "../../fixtures/migrate/chrome-export-note.csv".into(),
                vault,
                &key,
            )
            .await?;

        let mut search = SearchIndex::new();
        let mut keeper = Gatekeeper::new(vault);
        keeper.unlock(&key).await?;
        search.add_folder(&keeper).await?;

        let first =
            search.find_by_label(keeper.id(), "mock.example.com", None);
        assert!(first.is_some());

        let doc = first.unwrap();
        if let Some((_meta, secret, _)) =
            keeper.read_secret(&doc.secret_id).await?
        {
            let comment = secret.user_data().comment();
            assert_eq!(Some("mock note"), comment);
        } else {
            panic!("expecting to read secret");
        }

        Ok(())
    }
}
