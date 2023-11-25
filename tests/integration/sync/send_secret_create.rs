use anyhow::Result;

use sos_net::client::{RemoteBridge, RemoteSync};

use crate::test_utils::{mock_note, spawn, teardown};

use super::{assert_local_remote_events_eq, num_events, simulate_device};

const TEST_ID: &str = "sync_create_secret";

/// Tests syncing create secret events between two
/// clients.
#[tokio::test]
async fn integration_sync_create_secret() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut device1 = simulate_device(TEST_ID, &server, 2).await?;
    let default_folder_id = device1.default_folder_id.clone();
    let origin = device1.origin.clone();
    let folders = device1.folders.clone();

    let mut device2 = device1.connect(1, None).await?;

    //println!("default folder {}", default_folder_id);

    // Create a secret in the primary owner which won't exist
    // in the second device
    let (meta, secret) = mock_note("note_first_owner", "send_events_secret");
    device1
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;

    // First client is now ahead
    assert_eq!(2, num_events(&mut device1.owner, &default_folder_id).await);
    assert_eq!(1, num_events(&mut device2.owner, &default_folder_id).await);

    // The other owner creates a secret which should trigger a pull
    // of the remote patch before applying changes
    let (meta, secret) = mock_note("note_second_owner", "send_events_secret");
    device2
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;

    // Second client is ahead
    assert_eq!(2, num_events(&mut device1.owner, &default_folder_id).await);
    assert_eq!(3, num_events(&mut device2.owner, &default_folder_id).await);

    // First client runs sync to pull down the additional secret
    assert!(device1.owner.sync().await.is_none());

    // Everyone is equal
    assert_eq!(3, num_events(&mut device1.owner, &default_folder_id).await);
    assert_eq!(3, num_events(&mut device2.owner, &default_folder_id).await);

    // Get the remote out of the owner so we can
    // assert on equality between local and remote
    let mut provider = device1.owner.delete_remote(&origin).unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");

    let mut provider = device2.owner.delete_remote(&origin).unwrap();
    let other_remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");

    assert_local_remote_events_eq(
        folders.clone(),
        &mut device1.owner,
        remote_provider,
    )
    .await?;

    assert_local_remote_events_eq(
        folders.clone(),
        &mut device2.owner,
        other_remote_provider,
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}
