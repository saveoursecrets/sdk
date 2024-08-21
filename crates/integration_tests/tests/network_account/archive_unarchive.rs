use crate::test_utils::{
    assert_local_remote_events_eq, mock, num_events,
    simulate_device_with_builder, spawn, teardown,
};
use anyhow::Result;
use sos_net::{sdk::prelude::*, AccountSync};

/// Tests moving to and from an archive folder.
#[tokio::test]
async fn network_sync_archive_unarchive() -> Result<()> {
    const TEST_ID: &str = "sync_archive_unarchive";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare a mock device
    let mut device1 =
        simulate_device_with_builder(TEST_ID, 2, Some(&server), |builder| {
            builder.create_archive(true).create_file_password(true)
        })
        .await?;
    let default_folder = device1.default_folder.clone();
    let origin = device1.origin.clone();
    let folders = device1.folders.clone();
    let archive_folder = device1.owner.archive_folder().await.unwrap();

    let mut device2 = device1.connect(1, None).await?;

    // Create a secret
    let (meta, secret) = mock::note(TEST_ID, TEST_ID);
    let SecretChange { id: secret_id, .. } = device1
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;

    // Sync so they both have the secret
    assert!(device1.owner.sync().await.first_error().is_none());
    assert!(device2.owner.sync().await.first_error().is_none());

    // Move to the archive
    let SecretMove { id: secret_id, .. } = device1
        .owner
        .archive(&default_folder, &secret_id, Default::default())
        .await?;

    // First client is now ahead in both folders
    assert_eq!(3, num_events(&mut device1.owner, default_folder.id()).await);
    assert_eq!(2, num_events(&mut device2.owner, default_folder.id()).await);

    assert_eq!(2, num_events(&mut device1.owner, archive_folder.id()).await);
    assert_eq!(1, num_events(&mut device2.owner, archive_folder.id()).await);

    // Second client syncs
    assert!(device2.owner.sync().await.first_error().is_none());

    // Events should be in sync now
    assert_eq!(3, num_events(&mut device1.owner, default_folder.id()).await);
    assert_eq!(3, num_events(&mut device2.owner, default_folder.id()).await);

    assert_eq!(2, num_events(&mut device1.owner, archive_folder.id()).await);
    assert_eq!(2, num_events(&mut device2.owner, archive_folder.id()).await);

    // Need the meta data to unarchive
    let (data, _) = device1
        .owner
        .read_secret(&secret_id, Some(archive_folder.clone()))
        .await?;

    // Unarchive the secret
    device1
        .owner
        .unarchive(&secret_id, data.meta(), Default::default())
        .await?;

    // First client is now ahead in both folders
    assert_eq!(4, num_events(&mut device1.owner, default_folder.id()).await);
    assert_eq!(3, num_events(&mut device2.owner, default_folder.id()).await);

    assert_eq!(3, num_events(&mut device1.owner, archive_folder.id()).await);
    assert_eq!(2, num_events(&mut device2.owner, archive_folder.id()).await);

    // Second client syncs to get up to date
    assert!(device2.owner.sync().await.first_error().is_none());

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
