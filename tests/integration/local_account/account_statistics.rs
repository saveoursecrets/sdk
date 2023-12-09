use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use maplit2::{hashmap, hashset};
use sos_net::sdk::prelude::*;

const TEST_ID: &str = "account_statistics";

/// Tests the account statistics.
#[tokio::test]
async fn integration_account_statistics() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let (mut account, new_account) = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    let default_folder = new_account.default_folder();
    let key: AccessKey = password.into();
    account.sign_in(&key).await?;
    account.list_folders().await?;
    account.open_folder(&default_folder).await?;

    let statistics = account.statistics().await;
    assert_eq!(0, statistics.documents);
    assert!(statistics.folders.is_empty());
    assert!(statistics.tags.is_empty());
    assert!(statistics.types.is_empty());
    assert_eq!(0, statistics.favorites);

    // Create a login
    let tags = hashset! {
        "foo".to_owned(),
        "bar".to_owned()
    };
    let (login_password, _) = generate_passphrase()?;
    let (mut meta, secret) = mock::login("login", TEST_ID, login_password);
    meta.set_favorite(true);
    meta.set_tags(tags);
    account
        .create_secret(meta, secret, Default::default())
        .await?;

    let statistics = account.statistics().await;
    assert_eq!(1, statistics.documents);
    assert!(statistics.folders.contains(&(default_folder.clone(), 1)));
    assert_eq!(Some(&1), statistics.types.get(&SecretType::Account));
    assert_eq!(Some(&1), statistics.tags.get("foo"));
    assert_eq!(Some(&1), statistics.tags.get("bar"));
    assert_eq!(1, statistics.favorites);

    // Create a note
    let tags = hashset! {
        "foo".to_owned(),
    };
    let (mut meta, secret) = mock::note("note", TEST_ID);
    meta.set_tags(tags);
    account
        .create_secret(meta, secret, Default::default())
        .await?;

    let statistics = account.statistics().await;
    assert_eq!(2, statistics.documents);
    assert!(statistics.folders.contains(&(default_folder.clone(), 2)));
    assert_eq!(Some(&1), statistics.types.get(&SecretType::Note));
    assert_eq!(Some(&2), statistics.tags.get("foo"));
    assert_eq!(Some(&1), statistics.tags.get("bar"));

    // Create a card
    let (meta, secret) = mock::card("card", TEST_ID, "123");
    account
        .create_secret(meta, secret, Default::default())
        .await?;
    let statistics = account.statistics().await;
    assert_eq!(3, statistics.documents);
    assert!(statistics.folders.contains(&(default_folder.clone(), 3)));
    assert_eq!(Some(&1), statistics.types.get(&SecretType::Card));

    // Create a bank account
    let (meta, secret) = mock::bank("bank", TEST_ID, "12-34-56");
    account
        .create_secret(meta, secret, Default::default())
        .await?;
    let statistics = account.statistics().await;
    assert_eq!(4, statistics.documents);
    assert!(statistics.folders.contains(&(default_folder.clone(), 4)));
    assert_eq!(Some(&1), statistics.types.get(&SecretType::Bank));

    // Create a list
    let items = hashmap! {
        "a" => "1",
        "b" => "2",
    };
    let (meta, secret) = mock::list("list", items);
    account
        .create_secret(meta, secret, Default::default())
        .await?;
    let statistics = account.statistics().await;
    assert_eq!(5, statistics.documents);
    assert!(statistics.folders.contains(&(default_folder.clone(), 5)));
    assert_eq!(Some(&1), statistics.types.get(&SecretType::List));

    // Create a PEM-encoded certificate
    let (meta, secret) = mock::pem("pem");
    account
        .create_secret(meta, secret, Default::default())
        .await?;
    let statistics = account.statistics().await;
    assert_eq!(6, statistics.documents);
    assert!(statistics.folders.contains(&(default_folder.clone(), 6)));
    assert_eq!(Some(&1), statistics.types.get(&SecretType::Pem));

    // Create an internal file
    let (meta, secret) = mock::internal_file(
        "file",
        "file_name.txt",
        "text/plain",
        "file_contents".as_bytes(),
    );
    account
        .create_secret(meta, secret, Default::default())
        .await?;
    let statistics = account.statistics().await;
    assert_eq!(7, statistics.documents);
    assert!(statistics.folders.contains(&(default_folder.clone(), 7)));
    assert_eq!(Some(&1), statistics.types.get(&SecretType::File));

    // Create a link
    let (meta, secret) = mock::link("link", "https://example.com");
    account
        .create_secret(meta, secret, Default::default())
        .await?;
    let statistics = account.statistics().await;
    assert_eq!(8, statistics.documents);
    assert!(statistics.folders.contains(&(default_folder.clone(), 8)));
    assert_eq!(Some(&1), statistics.types.get(&SecretType::Link));

    // Create a password
    let (password, _) = generate_passphrase()?;
    let (meta, secret) = mock::password("password", password);
    account
        .create_secret(meta, secret, Default::default())
        .await?;
    let statistics = account.statistics().await;
    assert_eq!(9, statistics.documents);
    assert!(statistics.folders.contains(&(default_folder.clone(), 9)));
    assert_eq!(Some(&1), statistics.types.get(&SecretType::Password));

    // Create an AGE identity
    let (meta, secret) = mock::age("age");
    account
        .create_secret(meta, secret, Default::default())
        .await?;
    let statistics = account.statistics().await;
    assert_eq!(10, statistics.documents);
    assert!(statistics.folders.contains(&(default_folder.clone(), 10)));
    assert_eq!(Some(&1), statistics.types.get(&SecretType::Age));

    // Create an identity document
    let (meta, secret) =
        mock::identity("identity", IdentityKind::IdCard, "1234567890");
    account
        .create_secret(meta, secret, Default::default())
        .await?;
    let statistics = account.statistics().await;
    assert_eq!(11, statistics.documents);
    assert!(statistics.folders.contains(&(default_folder.clone(), 11)));
    assert_eq!(Some(&1), statistics.types.get(&SecretType::Identity));

    // Create a TOTP
    let (meta, secret) = mock::totp("totp");
    account
        .create_secret(meta, secret, Default::default())
        .await?;
    let statistics = account.statistics().await;
    assert_eq!(12, statistics.documents);
    assert!(statistics.folders.contains(&(default_folder.clone(), 12)));
    assert_eq!(Some(&1), statistics.types.get(&SecretType::Totp));

    // Create a contact
    let (meta, secret) = mock::contact("contact", "Jane Doe");
    account
        .create_secret(meta, secret, Default::default())
        .await?;
    let statistics = account.statistics().await;
    assert_eq!(13, statistics.documents);
    assert!(statistics.folders.contains(&(default_folder.clone(), 13)));
    assert_eq!(Some(&1), statistics.types.get(&SecretType::Contact));

    // Create a page
    let (meta, secret) = mock::page("page", "Title", "Body");
    account
        .create_secret(meta, secret, Default::default())
        .await?;
    let statistics = account.statistics().await;
    assert_eq!(14, statistics.documents);
    assert!(statistics.folders.contains(&(default_folder.clone(), 14)));
    assert_eq!(Some(&1), statistics.types.get(&SecretType::Page));

    // Create a folder and add a secret to the folder
    let folder_name = "folder_name";
    let (folder, _, _) =
        account.create_folder(folder_name.to_string()).await?;
    let (login_password, _) = generate_passphrase()?;
    let (mut meta, secret) = mock::login("login", TEST_ID, login_password);
    meta.set_favorite(true);
    let options = AccessOptions {
        folder: Some(folder.clone()),
        ..Default::default()
    };
    account.create_secret(meta, secret, options).await?;

    let statistics = account.statistics().await;
    assert_eq!(15, statistics.documents);
    assert!(statistics.folders.contains(&(default_folder.clone(), 14)));
    assert!(statistics.folders.contains(&(folder.clone(), 1)));
    assert_eq!(Some(&2), statistics.types.get(&SecretType::Account));
    assert_eq!(2, statistics.favorites);

    teardown(TEST_ID).await;

    Ok(())
}
