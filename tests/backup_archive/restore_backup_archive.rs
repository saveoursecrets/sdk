use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use maplit2::hashmap;
use sos_net::sdk::prelude::*;

const TEST_ID: &str = "backup_export_restore";

/// Tests creating a backup and restoring from the
/// backup archive then asserting on the restored data.
#[tokio::test]
async fn export_restore() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;
    let address = account.address().clone();

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

    let results = account.insert_secrets(docs).await?;
    let ids: Vec<_> = results.into_iter().map(|r| r.0).collect();

    // Export a backup archive
    let archive = data_dir.join("backup.zip");
    account.export_backup_archive(&archive).await?;
    assert!(vfs::try_exists(&archive).await?);

    // Delete all the secrets
    for id in &ids {
        account.delete_secret(id, Default::default()).await?;
    }

    // Restore from the backup archive
    let options = RestoreOptions {
        selected: folders.clone(),
        ..Default::default()
    };
    LocalAccount::restore_backup_archive(
        &archive,
        &mut account,
        password.clone(),
        options,
        Some(data_dir.clone()),
    )
    .await?;

    for id in ids {
        assert!(account.read_secret(&id, Default::default()).await.is_ok());
    }

    teardown(TEST_ID).await;

    Ok(())
}
