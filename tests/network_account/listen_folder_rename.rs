use crate::test_utils::{
    assert_local_remote_events_eq, assert_local_remote_vaults_eq,
    simulate_device, spawn, sync_pause, teardown,
};
use anyhow::Result;
use sos_net::sdk::prelude::*;

/// Tests syncing folder rename events between two clients
/// where the second client listens for changes emitted
/// by the first client via the remote.
#[tokio::test]
async fn network_sync_listen_folder_rename() -> Result<()> {
    const TEST_ID: &str = "sync_listen_folder_rename";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut device1 = simulate_device(TEST_ID, 2, Some(&server)).await?;
    let default_folder = device1.default_folder.clone();
    let origin = device1.origin.clone();
    let folders = device1.folders.clone();
    let server_path = device1.server_path.clone();
    let mut device2 = device1.connect(1, None).await?;

    // Start listening for change notifications
    device1.listen().await?;
    device2.listen().await?;

    let FolderChange { sync_error, .. } = device1
        .owner
        .rename_folder(&default_folder, "new_name".to_string())
        .await?;
    assert!(sync_error.is_none());

    // Pause a while to give the listener some time to process
    // the change notification
    sync_pause(None).await;

    // Assert first device
    let mut bridge = device1.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_vaults_eq(
        folders.clone(),
        &server_path,
        &mut device1.owner,
        &mut bridge,
    )
    .await?;
    assert_local_remote_events_eq(
        folders.clone(),
        &mut device1.owner,
        &mut bridge,
    )
    .await?;

    // Assert second device
    let mut bridge = device2.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_vaults_eq(
        folders.clone(),
        &server_path,
        &mut device2.owner,
        &mut bridge,
    )
    .await?;
    assert_local_remote_events_eq(folders, &mut device2.owner, &mut bridge)
        .await?;

    device1.owner.sign_out().await?;
    device2.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
