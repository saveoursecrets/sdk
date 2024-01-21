use crate::test_utils::{
    assert_local_remote_events_eq, mock, num_events, simulate_device, spawn,
    teardown,
};
use anyhow::Result;
use sos_net::{client::RemoteSync, sdk::prelude::*};

/// Tests syncing create secret events between two
/// clients.
#[tokio::test]
async fn network_sync_secret_create() -> Result<()> {
    const TEST_ID: &str = "sync_secret_create";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut device1 = simulate_device(TEST_ID, 2, Some(&server)).await?;
    let default_folder_id = device1.default_folder_id.clone();
    let origin = device1.origin.clone();
    let folders = device1.folders.clone();

    let mut device2 = device1.connect(1, None).await?;

    //println!("default folder {}", default_folder_id);

    // Create a secret in the primary owner which won't exist
    // in the second device
    let (meta, secret) = mock::note("note_first_owner", "send_events_secret");
    device1
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;

    // First client is now ahead
    assert_eq!(2, num_events(&mut device1.owner, &default_folder_id).await);
    assert_eq!(1, num_events(&mut device2.owner, &default_folder_id).await);

    // The other owner creates a secret which should trigger a pull
    // of the remote patch before applying changes
    let (meta, secret) =
        mock::note("note_second_owner", "send_events_secret");
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
    let mut bridge = device1.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_events_eq(
        folders.clone(),
        &mut device1.owner,
        &mut bridge,
    )
    .await?;

    let mut bridge = device2.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_events_eq(
        folders.clone(),
        &mut device2.owner,
        &mut bridge,
    )
    .await?;

    device1.owner.sign_out().await?;
    device2.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
