use super::{assert_local_remote_events_eq, num_events, simulate_device};
use crate::test_utils::{mock, spawn, sync_pause, teardown};
use anyhow::Result;
use sos_net::client::{RemoteBridge, RemoteSync};

const TEST_ID: &str = "sync_offline_manual";

/// Tests syncing events between two clients after
/// a server goes offline and a client commits changes
/// to local storage whilst disconnected.
#[tokio::test]
async fn integration_sync_offline_manual() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;
    let addr = server.addr.clone();

    // Prepare mock devices
    let mut device1 = simulate_device(TEST_ID, &server, 2).await?;
    let default_folder_id = device1.default_folder_id.clone();
    let origin = device1.origin.clone();
    let folders = device1.folders.clone();
    let mut device2 = device1.connect(1, None).await?;

    //println!("default folder {}", default_folder_id);

    // Oh no, the server has gone offline!
    drop(server);
    // Wait a while to make sure the server has gone
    sync_pause().await;

    // Perform all the basic CRUD operations to make sure
    // we are not affected by the remote being offline
    let (meta, secret) = mock::note("note", "offline_secret");
    let (id, sync_error) = device1
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;
    assert!(sync_error.is_some());
    let (_, _) = device1.owner.read_secret(&id, Default::default()).await?;
    let (meta, secret) = mock::note("note_edited", "offline_secret_edit");
    let (_, sync_error) = device1
        .owner
        .update_secret(&id, meta, Some(secret), Default::default(), None)
        .await?;
    assert!(sync_error.is_some());
    let sync_error =
        device1.owner.delete_secret(&id, Default::default()).await?;
    assert!(sync_error.is_some());

    // The first client is now very much ahead of the second client
    assert_eq!(4, num_events(&mut device1.owner, &default_folder_id).await);
    assert_eq!(1, num_events(&mut device2.owner, &default_folder_id).await);

    // Let's bring the server back online using
    // the same bind address so we don't need to
    // update the remote origin
    let _server = spawn(TEST_ID, Some(addr), None).await?;

    // Client explicitly syncs with the remote, either
    // they detected the server was back online or maybe
    // they signed in again (which is a natural time to sync).
    //
    // This should push the local changes to the remote.
    let result = device1.owner.sync().await;

    assert!(device1.owner.sync().await.is_none());

    // The client explicitly sync from the other device too.
    assert!(device2.owner.sync().await.is_none());

    // Now both devices should be up to date
    assert_eq!(4, num_events(&mut device1.owner, &default_folder_id).await);
    assert_eq!(4, num_events(&mut device2.owner, &default_folder_id).await);

    // Get the remote out of the owner so we can
    // assert on equality between local and remote
    let mut provider = device1
        .owner
        .delete_remote(&(&origin).into())
        .await?
        .unwrap();
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

    let mut provider = device2
        .owner
        .delete_remote(&(&origin).into())
        .await?
        .unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");

    assert_local_remote_events_eq(
        folders,
        &mut device2.owner,
        remote_provider,
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}
