use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use maplit2::hashmap;
use sos_account::{Account, LocalAccount};
use sos_filesystem::archive::RestoreOptions;
use sos_sdk::prelude::*;
use sos_test_utils::make_client_backend;

const TEST_ID: &str = "backup_export_import";

/// Tests creating a backup and importing from the
/// backup archive then asserting on the restored data.
#[tokio::test]
async fn backup_export_import() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    let paths = Paths::new_global(&data_dir);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        make_client_backend(&paths),
        Some(data_dir.clone()),
    )
    .await?;
    let account_id = account.account_id().clone();

    let key: AccessKey = password.clone().into();
    let folders = account.sign_in(&key).await?;
    let default_folder = account.default_folder().await.unwrap();

    let docs = vec![
        mock::login("login", TEST_ID, generate_passphrase()?.0),
        mock::note("note", "secret"),
        mock::card("card", TEST_ID, "123"),
        mock::bank("bank", TEST_ID, "12-34-56"),
        mock::list(
            "list",
            hashmap! {
                "a" => "1",
                "b" => "2",
            },
        ),
        mock::pem("pem"),
        mock::internal_file(
            "file",
            "file_name.txt",
            "text/plain",
            "file_contents".as_bytes(),
        ),
        mock::link("link", "https://example.com"),
        mock::password("password", generate_passphrase()?.0),
        mock::age("age"),
        mock::identity("identity", IdentityKind::IdCard, "1234567890"),
        mock::totp("totp"),
        mock::contact("contact", "Jane Doe"),
        mock::page("page", "Title", "Body"),
    ];

    let bulk = account.insert_secrets(docs).await?;
    let ids: Vec<_> = bulk.results.into_iter().map(|r| r.id).collect();

    // Export a backup archive
    let archive = data_dir.join("backup.zip");
    account.export_backup_archive(&archive).await?;
    assert!(vfs::try_exists(&archive).await?);

    // Delete the account
    account.delete_account().await?;
    assert!(!account.is_authenticated().await);

    // Restore from the backup archive
    let options = RestoreOptions {
        selected: folders.clone(),
        ..Default::default()
    };
    LocalAccount::import_backup_archive(
        &archive,
        options,
        Some(data_dir.clone()),
    )
    .await?;

    // Sign in after restoring the account
    let mut account = LocalAccount::new_unauthenticated(
        account_id,
        make_client_backend(&paths),
        Some(data_dir.clone()),
    )
    .await?;

    account.sign_in(&key).await?;
    account.open_folder(default_folder.id()).await?;

    for id in ids {
        assert!(account.read_secret(&id, Default::default()).await.is_ok());
    }

    teardown(TEST_ID).await;

    Ok(())
}
