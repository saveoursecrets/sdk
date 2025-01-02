use anyhow::Result;
use sos_database::search::SearchIndex;
use sos_migrate::import::csv::macos::{parse_path, MacPasswordCsv};
use sos_migrate::Convert;
use sos_password::diceware::generate_passphrase;
use sos_sdk::{
    crypto::AccessKey,
    vault::{BuilderCredentials, Gatekeeper, VaultBuilder},
};
use url::Url;

#[tokio::test]
async fn macos_passwords_csv_parse() -> Result<()> {
    let mut records =
        parse_path("../fixtures/migrate/macos-export.csv").await?;
    assert_eq!(2, records.len());

    let first = records.remove(0);
    let second = records.remove(0);

    assert_eq!("mock.example.com (mock@example.com)", &first.title);
    assert_eq!(Some(Url::parse("https://mock.example.com/")?), first.url);
    assert_eq!("mock@example.com", &first.username);
    assert_eq!("XXX-MOCK-1", &first.password);
    assert!(first.otp_auth.is_none());

    assert_eq!("mock2.example.com (mock-username)", &second.title);
    assert_eq!(Some(Url::parse("https://mock2.example.com/")?), second.url);
    assert_eq!("mock-username", &second.username);
    assert_eq!("XXX-MOCK-2", &second.password);
    assert!(second.otp_auth.is_none());

    Ok(())
}

#[tokio::test]
async fn macos_passwords_csv_convert() -> Result<()> {
    let (passphrase, _) = generate_passphrase()?;
    let vault = VaultBuilder::new()
        .build(BuilderCredentials::Password(passphrase.clone(), None))
        .await?;

    let key: AccessKey = passphrase.into();
    let vault = MacPasswordCsv
        .convert("../fixtures/migrate/macos-export.csv".into(), vault, &key)
        .await?;

    let mut search = SearchIndex::new();
    let mut keeper = Gatekeeper::new(vault);
    keeper.unlock(&key).await?;
    search.add_folder(&keeper).await?;

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
        .build(BuilderCredentials::Password(passphrase.clone(), None))
        .await?;

    let key: AccessKey = passphrase.into();
    let vault = MacPasswordCsv
        .convert(
            "../../fixtures/migrate/macos-notes-export.csv".into(),
            vault,
            &key,
        )
        .await?;

    let mut search = SearchIndex::new();
    let mut keeper = Gatekeeper::new(vault);
    keeper.unlock(&key).await?;
    search.add_folder(&keeper).await?;

    let first = search.find_by_label(
        keeper.id(),
        "mock.example.com (mock@example.com)",
        None,
    );
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
