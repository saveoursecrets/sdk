use crate::test_utils::{
    assert_local_remote_events_eq, mock, num_events, simulate_device, spawn,
    sync_pause, teardown,
};
use anyhow::Result;
use sos_net::sdk::prelude::*;

/// Tests syncing events between multiple clients.
///
/// Verifies the server is broadasting change
/// notifications as expected.
#[tokio::test]
async fn network_sync_listen_multiple() -> Result<()> {
    const TEST_ID: &str = "sync_listen_multiple";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut device1 = simulate_device(TEST_ID, 3, Some(&server)).await?;
    let default_folder_id = device1.default_folder_id.clone();
    let origin = device1.origin.clone();
    let folders = device1.folders.clone();
    let mut device2 = device1.connect(1, None).await?;
    let mut device3 = device1.connect(2, None).await?;

    // Start listening for change notifications
    device1.listen().await?;
    device2.listen().await?;
    device3.listen().await?;

    //println!("default folder {}", default_folder_id);

    // Create a secret in the primary owner which won't exist
    // in the second device
    let (meta, secret) = mock::note("note_first_owner", "send_events_secret");
    let result = device1
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;
    assert!(result.sync_result.first_error().is_none());

    /*
    // First client is now ahead
    assert_eq!(2, num_events(&mut device1.owner, &default_folder_id).await);
    assert_eq!(1, num_events(&mut device2.owner, &default_folder_id).await);
    assert_eq!(1, num_events(&mut device3.owner, &default_folder_id).await);
    */

    // Pause a while to give the listener some time to process
    // the change notification
    sync_pause(Some(500)).await;

    // Both clients should be in sync now
    assert_eq!(2, num_events(&mut device1.owner, &default_folder_id).await);
    assert_eq!(2, num_events(&mut device2.owner, &default_folder_id).await);
    assert_eq!(2, num_events(&mut device3.owner, &default_folder_id).await);

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
    assert_local_remote_events_eq(
        folders.clone(),
        &mut device2.owner,
        &mut bridge,
    )
    .await?;

    // Assert third device
    let mut bridge = device3.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_events_eq(folders, &mut device3.owner, &mut bridge)
        .await?;

    device1.owner.sign_out().await?;
    device2.owner.sign_out().await?;
    device3.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
