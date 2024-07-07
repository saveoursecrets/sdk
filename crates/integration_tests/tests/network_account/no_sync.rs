use crate::test_utils::{setup, spawn, teardown};
use anyhow::Result;
use sos_net::{sdk::prelude::*, NetworkAccount, RemoteSync};

/// Tests syncing with the NO_SYNC flag set.
#[tokio::test]
async fn network_no_sync_create_account() -> Result<()> {
    const TEST_ID: &str = "no_sync_create_account";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    // Prepare the client account
    let mut account = NetworkAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        Default::default(),
    )
    .await?;
    let address = account.address().clone();

    // Sign in to the new account
    let key: AccessKey = password.clone().into();
    account.sign_in(&key).await?;

    // Create folder with NO_SYNC flag
    let options = NewFolderOptions {
        flags: VaultFlags::AUTHENTICATOR | VaultFlags::NO_SYNC,
        ..Default::default()
    };
    let FolderCreate { folder, .. } =
        account.create_folder(TEST_ID.to_owned(), options).await?;

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Configure the server on the client account
    account.add_server(server.origin.clone()).await?;

    assert!(account.sync().await.is_none());

    // Server should not contain the folder files
    // as the NO_SYNC flag was set before the first sync
    let server_paths = server.paths(&address);
    let server_vault_file = server_paths.vault_path(folder.id());
    let server_event_file = server_paths.event_log_path(folder.id());
    assert!(!server_vault_file.exists());
    assert!(!server_event_file.exists());

    account.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
