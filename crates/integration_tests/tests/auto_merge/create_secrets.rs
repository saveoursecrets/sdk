use crate::test_utils::{
    assert_local_remote_events_eq, mock, simulate_device, spawn, sync_pause,
    teardown,
};
use anyhow::Result;
use sos_net::{sdk::prelude::*, RemoteSync};

/// Tests making conflicting changes to a folder whilst
/// a server is offline and resolving the conflicts with
/// an auto merge.
#[tokio::test]
async fn auto_merge_create_secrets() -> Result<()> {
    const TEST_ID: &str = "auto_merge_create_secrets";
    // crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;
    let addr = server.addr.clone();

    // Prepare mock devices
    let mut device1 = simulate_device(TEST_ID, 2, Some(&server)).await?;
    let origin = device1.origin.clone();
    let folders = device1.folders.clone();
    let default_folder = device1.default_folder.clone();
    let mut device2 = device1.connect(1, None).await?;

    // Oh no, the server has gone offline!
    drop(server);
    // Wait a while to make sure the server has gone
    sync_pause(None).await;

    // Create a secret on first device and fail to sync
    let (meta, secret) = mock::note("note_1", "offline_secret_1");
    let result1 = device1
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;
    assert!(result1.sync_error.is_some());

    // Create a secret on second device and fail to sync
    let (meta, secret) = mock::note("note_2", "offline_secret_2");
    let result2 = device2
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;
    assert!(result2.sync_error.is_some());

    let device1_folder_state =
        device1.owner.commit_state(&default_folder).await?;
    let device2_folder_state =
        device2.owner.commit_state(&default_folder).await?;

    // Folder commits has diverged
    assert_ne!(device1_folder_state, device2_folder_state);

    // Let's bring the server back online using
    // the same bind address so we don't need to
    // update the remote origin
    let _server = spawn(TEST_ID, Some(addr), None).await?;

    // Sync the first device
    assert!(device1.owner.sync().await.is_none());

    // Sync the second device which will auto merge local
    // changes with the remote so it has both secrets
    let sync_error = device2.owner.sync().await;
    assert!(sync_error.is_none());

    // Second device now has both secrets
    let (s1, _) = device2
        .owner
        .read_secret(&result1.id, Default::default())
        .await?;
    let (s2, _) = device2
        .owner
        .read_secret(&result2.id, Default::default())
        .await?;
    assert_eq!("note_1", s1.meta().label());
    assert_eq!("note_2", s2.meta().label());

    // Check the search index
    let documents =
        device2.owner.query_map("note", Default::default()).await?;
    assert_eq!(2, documents.len());

    // First device doesn't have the second secret yet!
    let err = device1
        .owner
        .read_secret(&result2.id, Default::default())
        .await
        .err()
        .unwrap();
    assert!(err.is_secret_not_found());

    // Sync the first device again to fetch the remote commits
    // that were changed when the auto merge executed
    assert!(device1.owner.sync().await.is_none());

    // First device now has both secrets
    let (s1, _) = device1
        .owner
        .read_secret(&result1.id, Default::default())
        .await?;
    let (s2, _) = device1
        .owner
        .read_secret(&result2.id, Default::default())
        .await?;
    assert_eq!("note_1", s1.meta().label());
    assert_eq!("note_2", s2.meta().label());

    // Check the search index
    let documents =
        device1.owner.query_map("note", Default::default()).await?;
    assert_eq!(2, documents.len());

    // Ensure all events are in sync
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
