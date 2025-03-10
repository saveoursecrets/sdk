use crate::test_utils::{
    assert_local_remote_events_eq, mock, num_events, simulate_device, spawn,
    sync_pause, teardown,
};
use anyhow::Result;
use sos_account::{Account, SecretChange, SecretDelete};
use sos_protocol::AccountSync;

/// Tests syncing events between two clients after
/// a server goes offline and a client commits changes
/// to local storage whilst disconnected.
#[tokio::test]
async fn network_sync_offline_manual() -> Result<()> {
    const TEST_ID: &str = "sync_offline_manual";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;
    let addr = server.addr.clone();

    // Prepare mock devices
    let mut device1 = simulate_device(TEST_ID, 2, Some(&server)).await?;
    let default_folder_id = device1.default_folder_id.clone();
    let origin = device1.origin.clone();
    let folders = device1.folders.clone();
    let mut device2 = device1.connect(1, None).await?;

    //println!("default folder {}", default_folder_id);

    // Oh no, the server has gone offline!
    drop(server);
    // Wait a while to make sure the server has gone
    sync_pause(None).await;

    // Perform all the basic CRUD operations to make sure
    // we are not affected by the remote being offline
    let (meta, secret) = mock::note("note", "offline_secret");
    let result = device1
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;
    assert!(result.sync_result.first_error().is_some());
    let (_, _) = device1
        .owner
        .read_secret(&result.id, Default::default())
        .await?;
    let (meta, secret) = mock::note("note_edited", "offline_secret_edit");
    let SecretChange { sync_result, .. } = device1
        .owner
        .update_secret(&result.id, meta, Some(secret), Default::default())
        .await?;
    assert!(sync_result.first_error().is_some());
    let SecretDelete { sync_result, .. } = device1
        .owner
        .delete_secret(&result.id, Default::default())
        .await?;
    assert!(sync_result.first_error().is_some());

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
    assert!(device1.owner.sync().await.first_error().is_none());

    // The client explicitly sync from the other device too.
    assert!(device2.owner.sync().await.first_error().is_none());

    // Now both devices should be up to date
    assert_eq!(4, num_events(&mut device1.owner, &default_folder_id).await);
    assert_eq!(4, num_events(&mut device2.owner, &default_folder_id).await);

    // Get the remote out of the owner so we can
    // assert on equality between local and remote
    let mut bridge = device1.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_events_eq(
        folders.clone(),
        &mut device1.owner,
        &mut bridge,
    )
    .await?;

    let mut bridge = device2.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_events_eq(folders, &mut device2.owner, &mut bridge)
        .await?;

    device1.owner.sign_out().await?;
    device2.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
