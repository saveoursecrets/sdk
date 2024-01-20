use crate::test_utils::{
    assert_local_remote_events_eq, mock, num_events, simulate_device, spawn,
    sync_pause, teardown,
};
use anyhow::Result;
use sos_net::sdk::prelude::*;

/// Tests syncing create folder events between two clients
/// where the second client listens for changes emitted
/// by the first client via the remote.
#[tokio::test]
async fn integration_sync_listen_create_folder() -> Result<()> {
    const TEST_ID: &str = "sync_listen_create_folder";

    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut device1 = simulate_device(TEST_ID, 2, Some(&server)).await?;
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

    let FolderCreate {
        folder: new_folder,
        sync_error,
        ..
    } = device1
        .owner
        .create_folder("sync_folder".to_string())
        .await?;
    assert!(sync_error.is_none());

    // Our new local folder should have the single create vault event
    assert_eq!(1, num_events(&mut device1.owner, new_folder.id()).await);

    // Pause a while to give the listener some time to process
    // the change notification
    sync_pause(None).await;

    // The synced client should also have the same number of events
    assert_eq!(1, num_events(&mut device2.owner, new_folder.id()).await);

    // Ensure we can open and write to the synced folder
    device2.owner.open_folder(&new_folder).await?;
    let (meta, secret) =
        mock::note("note_second_owner", "listen_create_folder");
    let result = device2
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;
    assert!(result.sync_error.is_none());

    // Pause a while to allow the first owner to sync
    // with the new change
    sync_pause(None).await;

    // Both client now have two events (create vault
    // and create secret)
    assert_eq!(2, num_events(&mut device1.owner, new_folder.id()).await);
    assert_eq!(2, num_events(&mut device2.owner, new_folder.id()).await);

    // Assert first device
    let mut bridge = device1.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_events_eq(
        folders.clone(),
        &mut device1.owner,
        &mut bridge,
    )
    .await?;

    // Assert second device
    let mut bridge = device2.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_events_eq(folders, &mut device2.owner, &mut bridge)
        .await?;

    device1.owner.sign_out().await?;
    device2.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
