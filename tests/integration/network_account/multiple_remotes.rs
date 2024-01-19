use crate::test_utils::{
    assert_local_remote_events_eq, mock, simulate_device, spawn, teardown,
};
use anyhow::Result;
use sos_net::{
    client::{RemoteBridge, RemoteSync},
    sdk::prelude::*,
};

/// Tests syncing a single client with multiple
/// remote servers.
#[tokio::test]
async fn integration_sync_multiple_remotes() -> Result<()> {
    const TEST_ID: &str = "sync_multiple_remotes";
    //crate::test_utils::init_tracing();

    // Spawn some backend servers
    let server1 = spawn(TEST_ID, None, Some("server1")).await?;
    let server2 = spawn(TEST_ID, None, Some("server2")).await?;

    // Prepare mock devices
    let mut device = simulate_device(TEST_ID, 1, Some(&server1)).await?;
    let folders = device.folders.clone();

    // Create a remote provider for the additional server
    let origin = server2.origin.clone();
    device.owner.add_server(origin.clone()).await?;

    // Sync again with the additional remote
    assert!(device.owner.sync().await.is_none());

    // Create a secret that should be synced to multiple remotes
    let (meta, secret) = mock::note("note", TEST_ID);
    device
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;

    // Assert on first server
    let mut provider = device
        .owner
        .remove_server(&(server1.origin).into())
        .await?
        .unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");
    assert_local_remote_events_eq(
        folders.clone(),
        &mut device.owner,
        remote_provider,
    )
    .await?;

    // Assert on second server
    let mut provider = device
        .owner
        .remove_server(&(server2.origin).into())
        .await?
        .unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");
    assert_local_remote_events_eq(
        folders.clone(),
        &mut device.owner,
        remote_provider,
    )
    .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
