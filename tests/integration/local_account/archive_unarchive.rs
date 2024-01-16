use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::sdk::prelude::*;

const TEST_ID: &str = "archive_unarchive";

/// Tests moving a secret to the archive and restoring
/// from the archive.
#[tokio::test]
async fn integration_archive_unarchive() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account_with_builder(
        account_name.clone(),
        password.clone(),
        |builder| builder.create_archive(true).create_file_password(true),
        Some(data_dir.clone()),
    )
    .await?;

    let key: AccessKey = password.into();
    account.sign_in(&key).await?;
    let default_folder = account.default_folder().await.unwrap();
    let archive_folder = account.archive_folder().await.unwrap();

    // Create secret
    let (meta, secret) = mock::note("note", TEST_ID);
    let SecretChange { id, folder, .. } = account
        .create_secret(meta.clone(), secret, Default::default())
        .await?;
    assert_eq!(&default_folder, &folder);

    // Archive the secret and get the new identifier
    let SecretMove { id, .. } = account
        .archive(&default_folder, &id, Default::default())
        .await?;

    let statistics = account.statistics().await;
    assert!(statistics.folders.contains(&(default_folder.clone(), 0)));
    assert!(statistics.folders.contains(&(archive_folder.clone(), 1)));

    // Move from the archive back to the default folder
    account
        .unarchive(&archive_folder, &id, &meta, Default::default())
        .await?;

    let statistics = account.statistics().await;
    assert!(statistics.folders.contains(&(default_folder.clone(), 1)));
    assert!(statistics.folders.contains(&(archive_folder.clone(), 0)));

    teardown(TEST_ID).await;

    Ok(())
}
