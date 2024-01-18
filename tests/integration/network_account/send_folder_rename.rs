use crate::test_utils::{
    assert_local_remote_events_eq, assert_local_remote_vaults_eq,
    simulate_device, spawn, teardown,
};
use anyhow::Result;
use sos_net::{client::RemoteBridge, sdk::prelude::*};

const TEST_ID: &str = "sync_rename_folder";

/// Tests sending create folder events to a remote.
#[tokio::test]
async fn integration_sync_rename_folder() -> Result<()> {
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

    let FolderChange { sync_error, .. } = device
        .owner
        .rename_folder(&default_folder, "new_name".to_string())
        .await?;
    assert!(sync_error.is_none());

    // Get the remote out of the owner so we can
    // assert on equality between local and remote
    let mut provider = device.owner.remove_server(&origin).await?.unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");

    assert_local_remote_vaults_eq(
        folders.clone(),
        &server_path,
        &mut device.owner,
        remote_provider,
    )
    .await?;

    assert_local_remote_events_eq(
        folders.clone(),
        &mut device.owner,
        remote_provider,
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}
