use crate::test_utils::{
    assert_local_remote_events_eq, mock, num_events, simulate_device, spawn,
    sync_pause, teardown,
};
use anyhow::Result;
use sos_net::sdk::prelude::*;

/// Tests syncing delete secret events between two clients
/// where the second client listens for changes emitted
/// by the first client via the remote.
#[tokio::test]
async fn network_sync_listen_secret_delete() -> Result<()> {
    const TEST_ID: &str = "sync_listen_secret_delete";
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

    // Create a secret in the primary owner which won't exist
    // in the second device
    let (meta, secret) = mock::note("note_first_owner", "send_events_secret");
    let result = device1
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;
    assert!(result.sync_error.is_none());

    // Delete the secret
    let SecretDelete { sync_error, .. } = device1
        .owner
        .delete_secret(&result.id, Default::default())
        .await?;
    assert!(sync_error.is_none());

    // Pause a while to give the listener some time to process
    // the change notification
    sync_pause(None).await;

    // Both clients should be in sync now
    assert_eq!(3, num_events(&mut device1.owner, &default_folder_id).await);
    assert_eq!(3, num_events(&mut device2.owner, &default_folder_id).await);

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
