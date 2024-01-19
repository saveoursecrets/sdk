use crate::test_utils::{
    assert_local_remote_events_eq, mock, simulate_device, spawn, sync_pause,
    teardown,
};
use anyhow::Result;
use sos_net::{
    client::{RemoteBridge, RemoteSync, SyncError},
    sdk::prelude::*,
};

/// Tests syncing a single client with multiple
/// remote servers when one of the servers is offline.
#[tokio::test]
async fn integration_sync_multiple_remotes_fallback() -> Result<()> {
    const TEST_ID: &str = "sync_multiple_remotes_fallback";
    //crate::test_utils::init_tracing();

    // Spawn some backend servers
    let server1 = spawn(TEST_ID, None, Some("server1")).await?;
    let server2 = spawn(TEST_ID, None, Some("server2")).await?;

    let addr = server1.addr.clone();

    // Prepare mock devices
    let mut device = simulate_device(TEST_ID, 1, Some(&server1)).await?;
    let folders = device.folders.clone();

    // Create a remote provider for the additional server
    let origin = server2.origin.clone();
    device.owner.add_server(origin.clone()).await?;

    // Sync again with the additional remote
    assert!(device.owner.sync().await.is_none());

    // Shutdown the first server
    drop(server1);
    sync_pause(None).await;

    // Create a secret that should be synced to multiple remotes
    let (meta, secret) = mock::note("note", TEST_ID);
    device
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;

    // Explicit sync afterwards, triggers the code path
    // where we try to connect to a remote which is down
    let sync_error = device.owner.sync().await;
    assert!(matches!(sync_error, Some(SyncError::Multiple(_))));

    // Bring the server back online
    let server1 = spawn(TEST_ID, Some(addr), Some("server1")).await?;
    sync_pause(None).await;

    // Now we should be able to sync to both remotes
    assert!(device.owner.sync().await.is_none());

    // Assert on first server
    let mut provider =
        device.owner.remove_server(&server1.origin).await?.unwrap();
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
    let mut provider =
        device.owner.remove_server(&server2.origin).await?.unwrap();
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
