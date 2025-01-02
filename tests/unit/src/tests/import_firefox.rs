use anyhow::Result;
use sos_database::search::SearchIndex;
use sos_migrate::import::csv::firefox::{parse_path, FirefoxPasswordCsv};
use sos_migrate::Convert;
use sos_password::diceware::generate_passphrase;
use sos_sdk::{
    crypto::AccessKey,
    vault::{BuilderCredentials, Gatekeeper, VaultBuilder},
};
use url::Url;

#[tokio::test]
async fn firefox_passwords_csv_parse() -> Result<()> {
    let mut records =
        parse_path("../fixtures/migrate/firefox-export.csv").await?;
    assert_eq!(2, records.len());

    let first = records.remove(0);
    let second = records.remove(0);

    assert_eq!(Url::parse("https://mock.example.com")?, first.url);
    assert_eq!("", &first.username);
    assert_eq!("XXX-MOCK-1", &first.password);

    assert_eq!(Url::parse("https://mock2.example.com")?, second.url);
    assert_eq!("mock-user-1", &second.username);
    assert_eq!("XXX-MOCK-2", &second.password);

    Ok(())
}

#[tokio::test]
async fn firefox_passwords_csv_convert() -> Result<()> {
    let (passphrase, _) = generate_passphrase()?;
    let vault = VaultBuilder::new()
        .build(BuilderCredentials::Password(passphrase.clone(), None))
        .await?;

    let key: AccessKey = passphrase.into();
    let vault = FirefoxPasswordCsv
        .convert("../fixtures/migrate/firefox-export.csv".into(), vault, &key)
        .await?;

    let mut search = SearchIndex::new();
    let mut keeper = Gatekeeper::new(vault);
    keeper.unlock(&key).await?;
    search.add_folder(&keeper).await?;

    let first =
        search.find_by_label(keeper.id(), "https://mock.example.com/", None);
    assert!(first.is_some());

    let second =
        search.find_by_label(keeper.id(), "https://mock2.example.com/", None);
    assert!(second.is_some());

    Ok(())
}
