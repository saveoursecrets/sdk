//! Parser for the MacOS passwords CSV export.

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
    /// Notes for the entry.
    #[serde(rename = "Notes")]
    pub notes: Option<String>,
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
            note: value.notes,
        }
    }
}

impl From<MacPasswordRecord> for GenericCsvEntry {
    fn from(value: MacPasswordRecord) -> Self {
        Self::Password(value.into())
    }
}

/// Parse records from a reader.
pub async fn parse_reader<R: AsyncRead + Unpin + Send>(
    reader: R,
) -> Result<Vec<MacPasswordRecord>> {
    read_csv_records::<MacPasswordRecord, _>(reader).await
}

/// Parse records from a path.
pub async fn parse_path<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<MacPasswordRecord>> {
    parse_reader(vfs::File::open(path).await?).await
}

/// Import a MacOS passwords CSV export into a vault.
pub struct MacPasswordCsv;

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl Convert for MacPasswordCsv {
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
    use super::{parse_path, MacPasswordCsv};
    use crate::Convert;
    use anyhow::Result;
    use tokio::sync::RwLock;

    use sos_sdk::{
        account::search::SearchIndex,
        passwd::diceware::generate_passphrase,
        vault::{Gatekeeper, VaultBuilder},
    };
    use std::sync::Arc;
    use url::Url;

    #[tokio::test]
    async fn macos_passwords_csv_parse() -> Result<()> {
        let mut records = parse_path("fixtures/macos-export.csv").await?;
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

    #[tokio::test]
    async fn macos_passwords_csv_convert() -> Result<()> {
        let (passphrase, _) = generate_passphrase()?;
        let vault = VaultBuilder::new()
            .password(passphrase.clone(), None)
            .await?;

        let vault = MacPasswordCsv
            .convert(
                "fixtures/macos-export.csv".into(),
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
        let first = search.find_by_label(
            keeper.id(),
            "mock.example.com (mock@example.com)",
            None,
        );
        assert!(first.is_some());

        let second = search.find_by_label(
            keeper.id(),
            "mock2.example.com (mock-username)",
            None,
        );
        assert!(second.is_some());

        Ok(())
    }

    #[tokio::test]
    async fn macos_passwords_notes_csv_convert() -> Result<()> {
        let (passphrase, _) = generate_passphrase()?;
        let vault = VaultBuilder::new()
            .password(passphrase.clone(), None)
            .await?;

        let vault = MacPasswordCsv
            .convert(
                "fixtures/macos-notes-export.csv".into(),
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
        let first = search.find_by_label(
            keeper.id(),
            "mock.example.com (mock@example.com)",
            None,
        );
        assert!(first.is_some());

        let doc = first.unwrap();
        if let Some((_meta, secret, _)) = keeper.read(&doc.secret_id).await? {
            let comment = secret.user_data().comment();
            assert_eq!(Some("mock note"), comment);
        } else {
            panic!("expecting to read secret");
        }

        Ok(())
    }
}
