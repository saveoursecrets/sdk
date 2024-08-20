use crate::test_utils::{
    assert_local_remote_events_eq, mock, simulate_device, spawn, teardown,
};
use anyhow::Result;
use sos_net::{sdk::prelude::*, AccountSync};

/// Tests recovering a folder from a remote origin after
/// it has been removed from the local account.
#[tokio::test]
async fn network_sync_recover_remote_folder() -> Result<()> {
    const TEST_ID: &str = "sync_recover_remote_folder";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let origin = device.origin.clone();

    // Create a folder
    let FolderCreate {
        folder: new_folder,
        sync_error,
        ..
    } = device
        .owner
        .create_folder(TEST_ID.to_string(), Default::default())
        .await?;
    assert!(sync_error.is_none());

    // Create a secret in the new folder
    let (meta, secret) = mock::note(TEST_ID, TEST_ID);
    let SecretChange { id, sync_error, .. } = device
        .owner
        .create_secret(meta.clone(), secret, new_folder.clone().into())
        .await?;
    assert!(sync_error.is_none());

    // Remove the folder files from the local account
    let paths = device.owner.paths();
    let vault_path = paths.vault_path(new_folder.id());
    let event_path = paths.event_log_path(new_folder.id());
    vfs::remove_file(&vault_path).await?;
    vfs::remove_file(&event_path).await?;

    // Sign out and sign in will put the account into the
    // inconsistent state as the folders will be reloaded
    // from disc which will cause subsequent sync operations
    // to fail.
    device.owner.sign_out().await?;
    let key: AccessKey = device.password.clone().into();
    device.owner.sign_in(&key).await?;

    // Now sync is broken as the local account is
    // in an inconsistent state
    let sync_error = device.owner.sync().await;
    assert!(sync_error.is_some());

    // Recover the folder from the remote origin
    device
        .owner
        .recover_remote_folder(&origin, new_folder.id())
        .await?;

    // Check we can read data immediately
    let (data, _) = device
        .owner
        .read_secret(&id, new_folder.clone().into())
        .await?;
    assert_eq!(meta.label(), data.meta().label());

    // Local should be back in sync with remote
    let folders = device.owner.list_folders().await?;
    let mut bridge = device.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_events_eq(folders, &mut device.owner, &mut bridge)
        .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
