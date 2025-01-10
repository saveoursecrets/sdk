use anyhow::Result;
use sos_database::search::SearchIndex;
use sos_migrate::import::csv::dashlane::{
    parse_path, DashlaneCsvZip, DashlaneRecord,
};
use sos_migrate::Convert;
use sos_password::diceware::generate_passphrase;
use sos_sdk::{
    crypto::AccessKey,
    vault::{secret::Secret, BuilderCredentials, AccessPoint, VaultBuilder},
};
use url::Url;

#[tokio::test]
async fn dashlane_csv_parse() -> Result<()> {
    let mut records =
        parse_path("../fixtures/migrate/dashlane-export.zip").await?;
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
        .build(BuilderCredentials::Password(passphrase.clone(), None))
        .await?;

    let key: AccessKey = passphrase.into();
    let vault = DashlaneCsvZip
        .convert(
            "../fixtures/migrate/dashlane-export.zip".into(),
            vault,
            &key,
        )
        .await?;

    let mut search = SearchIndex::new();
    let mut keeper = AccessPoint::new(vault);
    keeper.unlock(&key).await?;
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
        keeper.read_secret(card.as_ref().unwrap().id()).await?
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
