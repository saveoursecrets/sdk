use anyhow::Result;
use sos_database::search::SearchIndex;
use sos_migrate::import::csv::one_password::{parse_path, OnePasswordCsv};
use sos_migrate::import::csv::UNTITLED;
use sos_migrate::Convert;
use sos_password::diceware::generate_passphrase;
use sos_sdk::{
    crypto::AccessKey,
    vault::{BuilderCredentials, Gatekeeper, VaultBuilder},
};
use url::Url;

#[tokio::test]
async fn one_password_csv_parse() -> Result<()> {
    let mut records =
        parse_path("../fixtures/migrate/1password-export.csv").await?;
    assert_eq!(6, records.len());

    let first = records.remove(0);
    assert_eq!("Password (No Username)", first.title);
    assert_eq!(None, first.url);
    assert_eq!("", first.username,);
    assert_eq!("XXX-MOCK-1", first.password);
    assert_eq!("", first.tags);
    assert_eq!("", first.notes);
    assert!(!first.archived);
    assert!(!first.favorite);

    let second = records.remove(0);
    assert_eq!("Archive Password", second.title);
    assert_eq!(Some(Url::parse("https://example.com")?), second.url);
    assert_eq!("mock-user", second.username,);
    assert_eq!("XXX-MOCK-2", second.password);
    assert_eq!("mock;passwords", second.tags);
    assert_eq!("Archived password notes", second.notes);
    assert!(second.archived);
    assert!(!second.favorite);

    let third = records.remove(0);

    assert_eq!("", third.title);
    assert_eq!(None, third.url);
    assert_eq!("", third.username,);
    assert_eq!("", third.password);
    assert_eq!(
        "Mock notes about the mock password that was moved to the archive.",
        third.tags
    );
    assert_eq!("", third.notes);
    assert!(!third.archived);
    assert!(!third.favorite);

    let fourth = records.remove(0);
    assert_eq!("Mock Favorite Password", fourth.title);
    assert_eq!(None, fourth.url);
    assert_eq!("mock-user", fourth.username,);
    assert_eq!("XXX-MOCK-3", fourth.password);
    assert_eq!("mock", fourth.tags);
    assert_eq!("", fourth.notes);
    assert!(!fourth.archived);
    assert!(fourth.favorite);

    let fifth = records.remove(0);
    assert_eq!("Password (No Password)", fifth.title);
    assert_eq!(None, fifth.url);
    assert_eq!("mock-user", fifth.username,);
    assert_eq!("", fifth.password);
    assert_eq!("", fifth.tags);
    assert_eq!("", fifth.notes);
    assert!(!fifth.archived);
    assert!(!fifth.favorite);

    let sixth = records.remove(0);
    assert_eq!("Password (No username or password)", sixth.title);
    assert_eq!(None, sixth.url);
    assert_eq!("", sixth.username,);
    assert_eq!("", sixth.password);
    assert_eq!("", sixth.tags);
    assert_eq!("", sixth.notes);
    assert!(!sixth.archived);
    assert!(!sixth.favorite);

    Ok(())
}

#[tokio::test]
async fn one_password_csv_convert() -> Result<()> {
    let (passphrase, _) = generate_passphrase()?;
    let vault = VaultBuilder::new()
        .build(BuilderCredentials::Password(passphrase.clone(), None))
        .await?;

    let key: AccessKey = passphrase.into();
    let vault = OnePasswordCsv
        .convert(
            "../fixtures/migrate/1password-export.csv".into(),
            vault,
            &key,
        )
        .await?;

    let mut search = SearchIndex::new();
    let mut keeper = Gatekeeper::new(vault);
    keeper.unlock(&key).await?;
    search.add_folder(&keeper).await?;

    assert_eq!(6, search.len());

    let untitled = search.find_by_label(keeper.id(), UNTITLED, None);
    assert!(untitled.is_some());

    Ok(())
}
