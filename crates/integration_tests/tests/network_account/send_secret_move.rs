use crate::test_utils::{
    assert_local_remote_events_eq, mock, num_events, simulate_device, spawn,
    teardown,
};
use anyhow::Result;
use sos_net::{sdk::prelude::*, RemoteSync};

/// Tests syncing move secret events between two
/// clients.
#[tokio::test]
async fn network_sync_secret_move() -> Result<()> {
    const TEST_ID: &str = "sync_secret_move";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut device1 = simulate_device(TEST_ID, 2, Some(&server)).await?;
    let default_folder = device1.default_folder.clone();
    let origin = device1.origin.clone();
    let folders = device1.folders.clone();

    let mut device2 = device1.connect(1, None).await?;

    // Create a secret in the primary owner which won't exist
    // in the second device
    let (meta, secret) = mock::note(TEST_ID, TEST_ID);
    let SecretChange { id: secret_id, .. } = device1
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;

    let FolderCreate {
        folder: destination,
        ..
    } = device1
        .owner
        .create_folder("dest_folder".to_string(), Default::default())
        .await?;

    // Sync up both clients
    assert!(device1.owner.sync().await.is_none());
    assert!(device2.owner.sync().await.is_none());

    // Move the secret
    device1
        .owner
        .move_secret(
            &secret_id,
            &default_folder,
            &destination,
            Default::default(),
        )
        .await?;

    // First client is now ahead in the destination folder
    assert_eq!(2, num_events(&mut device1.owner, destination.id()).await);
    assert_eq!(1, num_events(&mut device2.owner, destination.id()).await);

    // Sync up both clients
    assert!(device1.owner.sync().await.is_none());
    assert!(device2.owner.sync().await.is_none());

    // Folder is now up to date
    assert_eq!(2, num_events(&mut device1.owner, destination.id()).await);
    assert_eq!(2, num_events(&mut device2.owner, destination.id()).await);

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
