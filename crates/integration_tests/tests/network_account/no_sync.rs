use crate::test_utils::{setup, simulate_device, spawn, teardown};
use anyhow::Result;
use sos_net::{
    protocol::{AccountSync, RemoteSyncHandler, SyncClient, SyncStorage},
    sdk::prelude::*,
    NetworkAccount,
};

/// Tests syncing with the NO_SYNC flag set before the account
/// exists on the remote server.
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

    assert!(account.sync().await.first_error().is_none());

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

/// Tests syncing with the NO_SYNC flag set after the account
/// has already been synced with the remote server.
#[tokio::test]
async fn network_no_sync_update_account() -> Result<()> {
    const TEST_ID: &str = "no_sync_update_account";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;
    let origin = server.origin.clone();

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 2, Some(&server)).await?;

    // Create folder with AUTHENTICATOR flag
    let options = NewFolderOptions {
        flags: VaultFlags::AUTHENTICATOR,
        ..Default::default()
    };
    let FolderCreate { folder, .. } = device
        .owner
        .create_folder(TEST_ID.to_owned(), options)
        .await?;

    // Sync the account to push the new folder
    assert!(device.owner.sync().await.first_error().is_none());

    // Update the folder with new flags.
    device
        .owner
        .update_folder_flags(
            &folder,
            VaultFlags::AUTHENTICATOR | VaultFlags::NO_SYNC,
        )
        .await?;

    // Sync the account again which should ignore the updates
    // to the new folder that has now been marked with NO_SYNC
    assert!(device.owner.sync().await.first_error().is_none());

    // Local should be equal with remote now.
    //
    // The folder is set to NO_SYNC which means it should not be
    // shared with other devices but we still want a copy on server(s)
    // for redundancy.
    let local_status = device.owner.sync_status().await?;
    let bridge = device.owner.remove_server(&origin).await?.unwrap();
    let remote_status = bridge.client().sync_status().await?;

    let local_folder = local_status.folders.get(folder.id()).unwrap();
    let remote_folder = remote_status.folders.get(folder.id()).unwrap();
    let local_proof = &local_folder.1;
    let remote_proof = &remote_folder.1;

    assert_eq!(local_proof.root, remote_proof.root);

    device.owner.sign_out().await?;
    teardown(TEST_ID).await;

    Ok(())
}
