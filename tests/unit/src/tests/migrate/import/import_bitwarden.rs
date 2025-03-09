#[cfg(test)]
mod test {
    use anyhow::Result;
    use sos_database::search::SearchIndex;
    use sos_migrate::import::csv::bitwarden::{parse_path, BitwardenCsv};
    use sos_migrate::Convert;
    use sos_password::diceware::generate_passphrase;
    use sos_sdk::{
        crypto::AccessKey,
        vault::{BuilderCredentials, AccessPoint, VaultBuilder},
    };
    use url::Url;

    #[tokio::test]
    async fn bitwarden_passwords_csv_parse() -> Result<()> {
        let mut records =
            parse_path("../fixtures/migrate/bitwarden-export.csv").await?;
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
                "../fixtures/migrate/bitwarden-export.csv".into(),
                vault,
                &key,
            )
            .await?;

        let mut search = SearchIndex::new();
        let mut keeper = AccessPoint::new(vault);
        keeper.unlock(&key).await?;
        search.add_folder(&keeper).await?;

        let first = search.find_by_label(keeper.id(), "Mock Login", None);
        assert!(first.is_some());

        let second = search.find_by_label(keeper.id(), "Mock Note", None);
        assert!(second.is_some());

        Ok(())
    }
}
