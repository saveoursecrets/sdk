use super::{assert_local_remote_events_eq, num_events, simulate_device};
use crate::test_utils::{mock_note, spawn, sync_pause, teardown};
use anyhow::Result;
use sos_net::client::RemoteBridge;

const TEST_ID: &str = "sync_listen_create_folder";

/// Tests syncing create folder events between two clients
/// where the second client listens for changes emitted
/// by the first client via the remote.
#[ignore = "need to sync the identity vault for this to work"]
#[tokio::test]
async fn integration_sync_listen_create_folder() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut device1 = simulate_device(TEST_ID, &server, 2).await?;
    let default_folder_id = device1.default_folder_id.clone();
    let origin = device1.origin.clone();
    let folders = device1.folders.clone();
    let mut device2 = device1.connect(1, None).await?;

    // Start listening for change notifications
    device1.listen().await?;
    device2.listen().await?;

    //println!("default folder {}", default_folder_id);

    // Before we begin both clients should have a single event
    assert_eq!(1, num_events(&mut device1.owner, &default_folder_id).await);
    assert_eq!(1, num_events(&mut device2.owner, &default_folder_id).await);

    let (new_folder, sync_error) = device1
        .owner
        .create_folder("sync_folder".to_string())
        .await?;
    assert!(sync_error.is_none());

    // Our new local folder should have the single create vault event
    assert_eq!(1, num_events(&mut device1.owner, new_folder.id()).await);

    // Pause a while to give the listener some time to process
    // the change notification
    sync_pause().await;

    // The synced client should also have the same number of events
    assert_eq!(1, num_events(&mut device2.owner, new_folder.id()).await);

    // Ensure we can open and write to the synced folder
    device2.owner.open_folder(&new_folder).await?;
    let (meta, secret) =
        mock_note("note_second_owner", "listen_create_folder");
    let (_, sync_error) = device2
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;
    assert!(sync_error.is_none());

    // Pause a while to allow the first owner to sync
    // with the new change
    sync_pause().await;

    // Both client now have two events (create vault
    // and create secret)
    assert_eq!(2, num_events(&mut device1.owner, new_folder.id()).await);
    assert_eq!(2, num_events(&mut device2.owner, new_folder.id()).await);

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

    assert_local_remote_events_eq(
        folders,
        &mut device2.owner,
        remote_provider,
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}