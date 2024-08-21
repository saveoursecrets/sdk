use crate::test_utils::{
    assert_local_remote_events_eq, assert_local_remote_vaults_eq,
    simulate_device, spawn, teardown,
};
use anyhow::Result;
use sos_net::sdk::prelude::*;

/// Tests sending create folder events to a remote.
#[tokio::test]
async fn network_sync_folder_rename() -> Result<()> {
    const TEST_ID: &str = "sync_folder_rename";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare a mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let origin = device.origin.clone();
    let default_folder = device.default_folder.clone();
    let folders = device.folders.clone();

    // Path that we expect the remote server to write to
    let server_path = server.account_path(device.owner.address());

    let FolderChange { sync_result, .. } = device
        .owner
        .rename_folder(&default_folder, "new_name".to_string())
        .await?;
    assert!(sync_result.first_error().is_none());

    // Get the remote out of the owner so we can
    // assert on equality between local and remote
    let mut bridge = device.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_vaults_eq(
        folders.clone(),
        &server_path,
        &mut device.owner,
        &mut bridge,
    )
    .await?;

    assert_local_remote_events_eq(
        folders.clone(),
        &mut device.owner,
        &mut bridge,
    )
    .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
