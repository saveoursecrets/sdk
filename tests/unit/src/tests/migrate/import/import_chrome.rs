use anyhow::Result;
use sos_database::search::SearchIndex;
use sos_migrate::import::csv::chrome::{parse_path, ChromePasswordCsv};
use sos_migrate::{import::csv::GenericPasswordRecord, Convert};
use sos_password::diceware::generate_passphrase;
use sos_sdk::{
    crypto::AccessKey,
    vault::{BuilderCredentials, Gatekeeper, VaultBuilder},
};
use url::Url;

#[tokio::test]
async fn chrome_passwords_csv_parse() -> Result<()> {
    let mut records =
        parse_path("../fixtures/migrate/chrome-export.csv").await?;
    assert_eq!(2, records.len());

    let first = records.remove(0);
    let second = records.remove(0);

    assert_eq!("mock.example.com", &first.name);
    assert_eq!(
        Some(
            "https://mock.example.com/login,https://mock.example.com/login2"
                .to_owned()
        ),
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
        .convert("../fixtures/migrate/chrome-export.csv".into(), vault, &key)
        .await?;

    let mut search = SearchIndex::new();
    let mut keeper = Gatekeeper::new(vault);
    keeper.unlock(&key).await?;
    search.add_folder(&keeper).await?;

    let first = search.find_by_label(keeper.id(), "mock.example.com", None);
    assert!(first.is_some());

    let second = search.find_by_label(keeper.id(), "mock2.example.com", None);
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
            "../fixtures/migrate/chrome-export-note.csv".into(),
            vault,
            &key,
        )
        .await?;

    let mut search = SearchIndex::new();
    let mut keeper = Gatekeeper::new(vault);
    keeper.unlock(&key).await?;
    search.add_folder(&keeper).await?;

    let first = search.find_by_label(keeper.id(), "mock.example.com", None);
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
