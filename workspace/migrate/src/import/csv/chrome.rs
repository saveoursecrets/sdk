//! Parser for the Chrome passwords CSV export.

use secrecy::SecretString;
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
    pub url: Option<Url>,
    /// The username for the entry.
    pub username: String,
    /// The password for the entry.
    pub password: String,
}

impl From<ChromePasswordRecord> for GenericPasswordRecord {
    fn from(value: ChromePasswordRecord) -> Self {
        let label = if value.name.is_empty() {
            UNTITLED.to_owned()
        } else {
            value.name
        };
        Self {
            label,
            url: value.url,
            username: value.username,
            password: value.password,
            otp_auth: None,
            tags: None,
            note: None,
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

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Convert for ChromePasswordCsv {
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
    use super::{parse_path, ChromePasswordCsv};
    use crate::Convert;
    use anyhow::Result;
    use tokio::sync::RwLock;

    use sos_sdk::{
        passwd::diceware::generate_passphrase,
        search::SearchIndex,
        vault::{Gatekeeper, VaultBuilder},
    };
    use std::sync::Arc;
    use url::Url;

    #[tokio::test]
    async fn chrome_passwords_csv_parse() -> Result<()> {
        let mut records = parse_path("fixtures/chrome-export.csv").await?;
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

    #[tokio::test]
    async fn chrome_passwords_csv_convert() -> Result<()> {
        let (passphrase, _) = generate_passphrase()?;
        let vault = VaultBuilder::new()
            .password(passphrase.clone(), None)
            .await?;

        let vault = ChromePasswordCsv
            .convert(
                "fixtures/chrome-export.csv".into(),
                vault,
                passphrase.clone().into(),
            )
            .await?;

        let search_index = Arc::new(RwLock::new(SearchIndex::new()));
        let mut keeper =
            Gatekeeper::new(vault, Some(Arc::clone(&search_index)));
        keeper.unlock(passphrase.into()).await?;
        keeper.create_search_index().await?;

        let search = search_index.read().await;
        let first =
            search.find_by_label(keeper.id(), "mock.example.com", None);
        assert!(first.is_some());

        let second =
            search.find_by_label(keeper.id(), "mock2.example.com", None);
        assert!(second.is_some());

        Ok(())
    }
}
