use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::sdk::prelude::*;

/// Tests querying the index after restoring from a backup archive.
#[tokio::test]
async fn integration_search_restore_archive() -> Result<()> {
    const TEST_ID: &str = "search_restore_archive";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
    )
    .await?;

    let key: AccessKey = password.clone().into();
    let folders = account.sign_in(&key).await?;

    // Create a secret
    let (meta, secret) = mock::note("note", TEST_ID);
    let SecretChange { id, .. } = account
        .create_secret(meta, secret, Default::default())
        .await?;

    // Export a backup archive
    let archive = data_dir.join("backup.zip");
    account.export_backup_archive(&archive).await?;
    assert!(vfs::try_exists(&archive).await?);

    // Delete the secret
    account.delete_secret(&id, Default::default()).await?;

    // Restore from the backup archive
    let options = RestoreOptions {
        selected: folders.clone(),
        ..Default::default()
    };
    account
        .restore_backup_archive(
            &archive,
            password.clone(),
            options,
            Some(data_dir.clone()),
        )
        .await?;

    // Check we can find the restored secret
    let documents = account.query_map("note", Default::default()).await?;
    assert_eq!(1, documents.len());

    teardown(TEST_ID).await;

    Ok(())
}
