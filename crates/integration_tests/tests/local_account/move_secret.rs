use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::sdk::prelude::*;

/// Tests moving a secret between folders.
#[tokio::test]
async fn local_move_secret() -> Result<()> {
    const TEST_ID: &str = "move_secret";
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

    let key: AccessKey = password.into();
    account.sign_in(&key).await?;
    let default_folder = account.default_folder().await.unwrap();

    // Create secret
    let (meta, secret) = mock::note("note", TEST_ID);
    let SecretChange { id, folder, .. } = account
        .create_secret(meta, secret, Default::default())
        .await?;
    assert_eq!(&default_folder, &folder);

    let statistics = account.statistics().await;
    assert!(statistics.folders.contains(&(default_folder.clone(), 1)));

    // Create a folder
    let folder_name = "folder_name";
    let FolderCreate { folder, .. } = account
        .create_folder(folder_name.to_string(), Default::default())
        .await?;

    // Move to the new folder
    account
        .move_secret(&id, &default_folder, &folder, Default::default())
        .await?;

    let statistics = account.statistics().await;
    assert!(statistics.folders.contains(&(default_folder.clone(), 0)));
    assert!(statistics.folders.contains(&(folder.clone(), 1)));

    teardown(TEST_ID).await;

    Ok(())
}
