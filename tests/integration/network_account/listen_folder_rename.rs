use crate::test_utils::{
    assert_local_remote_events_eq, assert_local_remote_vaults_eq,
    simulate_device, spawn, sync_pause, teardown,
};
use anyhow::Result;
use sos_net::client::RemoteBridge;

const TEST_ID: &str = "sync_listen_rename_folder";

/// Tests syncing folder rename events between two clients
/// where the second client listens for changes emitted
/// by the first client via the remote.
#[tokio::test]
async fn integration_sync_listen_rename_folder() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut device1 = simulate_device(TEST_ID, &server, 2).await?;
    let default_folder = device1.default_folder.clone();
    let origin = device1.origin.clone();
    let folders = device1.folders.clone();
    let server_path = device1.server_path.clone();
    let mut device2 = device1.connect(1, None).await?;

    // Start listening for change notifications
    device1.listen().await?;
    device2.listen().await?;

    let sync_error = device1
        .owner
        .rename_folder(&default_folder, "new_name".to_string())
        .await?;
    assert!(sync_error.is_none());

    // Pause a while to give the listener some time to process
    // the change notification
    sync_pause(None).await;

    // Assert first device
    let mut provider = device1
        .owner
        .delete_remote(&(&origin).into())
        .await?
        .unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");

    assert_local_remote_vaults_eq(
        folders.clone(),
        &server_path,
        &mut device1.owner,
        remote_provider,
    )
    .await?;

    assert_local_remote_events_eq(
        folders.clone(),
        &mut device1.owner,
        remote_provider,
    )
    .await?;

    // Assert second device
    let mut provider = device2
        .owner
        .delete_remote(&(&origin).into())
        .await?
        .unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");

    assert_local_remote_vaults_eq(
        folders.clone(),
        &server_path,
        &mut device2.owner,
        remote_provider,
    )
    .await?;

    assert_local_remote_events_eq(
        folders,
        &mut device2.owner,
        remote_provider,
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}
