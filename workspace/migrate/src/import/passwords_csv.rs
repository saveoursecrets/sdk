//! Parser for the MacOS passwords CSV export.

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use std::{
    io::Read,
    path::{Path, PathBuf},
};
use url::Url;

use sos_core::{
    secret::{Secret, SecretMeta},
    vault::Vault,
    Gatekeeper,
};

use crate::{Convert, Result};

/// Record for an entry in a MacOS passwords CSV export.
#[derive(Deserialize)]
pub struct MacPasswordRecord {
    /// The title of the entry.
    #[serde(rename = "Title")]
    pub title: String,
    /// The URL of the entry.
    #[serde(rename = "Url")]
    pub url: Url,
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
        source: Self::Input,
        vault: Vault,
        password: SecretString,
    ) -> crate::Result<Vault> {
        let records = parse_path(source)?;

        let mut keeper = Gatekeeper::new(vault, None);
        keeper.unlock(password.expose_secret())?;

        for entry in records {
            let secret = Secret::Account {
                account: entry.username,
                password: SecretString::new(entry.password),
                url: Some(entry.url),
                user_data: Default::default(),
            };
            let meta = SecretMeta::new(entry.title, secret.kind());
            keeper.create(meta, secret)?;
        }

        keeper.lock();
        Ok(keeper.take())
    }
}

#[cfg(test)]
mod test {
    use super::parse_path;
    use anyhow::Result;
    use url::Url;

    #[test]
    fn keychain_passwords_csv() -> Result<()> {
        let mut records =
            parse_path("fixtures/mock-macos-passwords-export.csv")?;
        assert_eq!(2, records.len());

        let first = records.remove(0);
        let second = records.remove(0);

        assert_eq!("mock.example.com (mock@example.com)", &first.title);
        assert_eq!(Url::parse("https://mock.example.com/")?, first.url);
        assert_eq!("mock@example.com", &first.username);
        assert_eq!("XXX-MOCK-1", &first.password);
        assert!(first.otp_auth.is_none());

        assert_eq!("mock2.example.com (mock-username)", &second.title);
        assert_eq!(Url::parse("https://mock2.example.com/")?, second.url);
        assert_eq!("mock-username", &second.username);
        assert_eq!("XXX-MOCK-2", &second.password);
        assert!(second.otp_auth.is_none());

        Ok(())
    }
}
