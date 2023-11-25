use super::{assert_local_remote_events_eq, simulate_device};
use crate::test_utils::{mock_note, sync_pause, spawn, teardown};
use anyhow::Result;
use sos_net::client::{RemoteBridge, RemoteSync};

const TEST_ID: &str = "sync_multiple_remotes_fallback";

/// Tests syncing a single client with multiple 
/// remote servers when one of the servers is offline.
#[tokio::test]
async fn integration_sync_multiple_remotes_fallback() -> Result<()> {
    crate::test_utils::init_tracing();

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
    device1.owner.insert_remote(origin.clone(), Box::new(provider));

    // Sync again with the additional remote
    device1.owner.sync().await?;
    
    // Shutdown the first server
    drop(server1);
    sync_pause().await;

    // Create a secret that should be synced to multiple remotes
    let (meta, secret) = mock_note("note", TEST_ID);
    device1
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;

    // Explicit sync afterwards, triggers the code path 
    // where we try to connect to a remote which is down
    device1.owner.sync().await?;
    
    /*
    // Assert on first server
    let mut provider = device1.owner.delete_remote(&server1.origin).unwrap();
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
    let mut provider = device1.owner.delete_remote(&server2.origin).unwrap();
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
    */

    teardown(TEST_ID).await;

    Ok(())
}
