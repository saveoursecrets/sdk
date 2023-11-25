use super::{assert_local_remote_events_eq, num_events, simulate_device};
use crate::test_utils::{mock_note, spawn, sync_pause, teardown};
use anyhow::Result;
use sos_net::client::RemoteBridge;

const TEST_ID: &str = "sync_listen_multiple";

/// Tests syncing events between multiple clients.
///
/// Verifies the server is broadasting change
/// notifications as expected.
#[tokio::test]
async fn integration_sync_listen_multiple() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut device1 = simulate_device(TEST_ID, &server, 3).await?;
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
    let (meta, secret) = mock_note("note_first_owner", "send_events_secret");
    let (_, sync_error) = device1
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;
    assert!(sync_error.is_none());

    // First client is now ahead
    assert_eq!(2, num_events(&mut device1.owner, &default_folder_id).await);
    assert_eq!(1, num_events(&mut device2.owner, &default_folder_id).await);
    assert_eq!(1, num_events(&mut device3.owner, &default_folder_id).await);

    // Pause a while to give the listener some time to process
    // the change notification
    sync_pause().await;

    // Both clients should be in sync now
    assert_eq!(2, num_events(&mut device1.owner, &default_folder_id).await);
    assert_eq!(2, num_events(&mut device2.owner, &default_folder_id).await);
    assert_eq!(2, num_events(&mut device3.owner, &default_folder_id).await);

    // Assert first device
    let mut provider = device1.owner.delete_remote(&origin).unwrap();
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
    let mut provider = device2.owner.delete_remote(&origin).unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");

    assert_local_remote_events_eq(
        folders.clone(),
        &mut device2.owner,
        remote_provider,
    )
    .await?;

    // Assert third device
    let mut provider = device3.owner.delete_remote(&origin).unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");

    assert_local_remote_events_eq(
        folders,
        &mut device3.owner,
        remote_provider,
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}
