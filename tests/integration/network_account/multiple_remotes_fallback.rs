use crate::test_utils::{
    assert_local_remote_events_eq, mock, simulate_device, spawn, sync_pause,
    teardown,
};
use anyhow::Result;
use sos_net::client::{RemoteBridge, RemoteSync, SyncError};

const TEST_ID: &str = "sync_multiple_remotes_fallback";

/// Tests syncing a single client with multiple
/// remote servers when one of the servers is offline.
#[tokio::test]
async fn integration_sync_multiple_remotes_fallback() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn some backend servers
    let server1 = spawn(TEST_ID, None, Some("server1")).await?;
    let server2 = spawn(TEST_ID, None, Some("server2")).await?;

    let addr = server1.addr.clone();

    // Prepare mock devices
    let mut device1 = simulate_device(TEST_ID, &server1, 1).await?;
    let folders = device1.folders.clone();

    // Create a remote provider for the additional server
    let origin = server2.origin.clone();
    let provider = device1.owner.remote_bridge(&origin).await?;
    device1
        .owner
        .insert_remote(origin.into(), Box::new(provider))
        .await?;

    // Sync again with the additional remote
    assert!(device1.owner.sync().await.is_none());

    // Shutdown the first server
    drop(server1);
    sync_pause(None).await;

    // Create a secret that should be synced to multiple remotes
    let (meta, secret) = mock::note("note", TEST_ID);
    device1
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;

    // Explicit sync afterwards, triggers the code path
    // where we try to connect to a remote which is down
    let sync_error = device1.owner.sync().await;
    assert!(matches!(sync_error, Some(SyncError::Multiple(_))));

    // Bring the server back online
    let server1 = spawn(TEST_ID, Some(addr), Some("server1")).await?;
    sync_pause(None).await;

    // Now we should be able to sync to both remotes
    assert!(device1.owner.sync().await.is_none());

    // Assert on first server
    let mut provider =
        device1.owner.delete_remote(&server1.origin).await?.unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");
    assert_local_remote_events_eq(
        folders.clone(),
        &mut device1.owner,
        remote_provider,
    )
    .await?;

    // Assert on second server
    let mut provider =
        device1.owner.delete_remote(&server2.origin).await?.unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");
    assert_local_remote_events_eq(
        folders.clone(),
        &mut device1.owner,
        remote_provider,
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}
