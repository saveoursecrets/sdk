use crate::test_utils::{
    assert_local_remote_events_eq, mock, simulate_device, spawn, sync_pause,
    teardown,
};
use anyhow::Result;
use sos_net::{sdk::prelude::*, RemoteSync};

/// Tests making conflicting edits to a folder whilst
/// a server is offline and resolving the conflicts with
/// an auto merge.
#[tokio::test]
async fn auto_merge_edit_secrets() -> Result<()> {
    const TEST_ID: &str = "auto_merge_edit_secrets";
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

    // Create a secret and sync so all devices have it
    let (meta, secret) = mock::note("note_1", TEST_ID);
    let result = device1
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;
    assert!(result.sync_error.is_none());

    // Sync to fetch the new secret on the second device
    assert!(device2.owner.sync().await.is_none());

    // Oh no, the server has gone offline!
    drop(server);
    // Wait a while to make sure the server has gone
    sync_pause(None).await;

    // Update the secret whilst offline on first device
    let (meta, secret) = mock::note("edit_1", TEST_ID);
    let SecretChange { sync_error, .. } = device1
        .owner
        .update_secret(
            &result.id,
            meta,
            Some(secret),
            Default::default(),
            None,
        )
        .await?;
    assert!(sync_error.is_some());

    // Update the secret whilst offline on second device
    let (meta, secret) = mock::note("edit_2", TEST_ID);
    let SecretChange { sync_error, .. } = device2
        .owner
        .update_secret(
            &result.id,
            meta,
            Some(secret),
            Default::default(),
            None,
        )
        .await?;
    assert!(sync_error.is_some());

    let device1_folder_state =
        device1.owner.commit_state(&default_folder).await?;
    let device2_folder_state =
        device2.owner.commit_state(&default_folder).await?;

    // Folder commits have diverged
    assert_ne!(device1_folder_state, device2_folder_state);

    // Let's bring the server back online using
    // the same bind address so we don't need to
    // update the remote origin
    let _server = spawn(TEST_ID, Some(addr), None).await?;

    // Sync first device to push changes
    assert!(device1.owner.sync().await.is_none());

    // Sync second device to auto merge
    assert!(device2.owner.sync().await.is_none());

    // Sync first device again to fetch auto merged changes
    assert!(device1.owner.sync().await.is_none());

    let device1_folder_state =
        device1.owner.commit_state(&default_folder).await?;
    let device2_folder_state =
        device2.owner.commit_state(&default_folder).await?;

    // Folder commits are back in sync
    assert_eq!(device1_folder_state, device2_folder_state);

    // Make sure both devices see the last edit
    let (row, _) = device1.owner.read_secret(&result.id, None).await?;
    assert_eq!("edit_2", row.meta().label());
    let (row, _) = device2.owner.read_secret(&result.id, None).await?;
    assert_eq!("edit_2", row.meta().label());

    // Check the search index (device1)
    let mut documents =
        device1.owner.query_map("edit", Default::default()).await?;
    assert_eq!(1, documents.len());
    let doc = documents.remove(0);
    assert_eq!("edit_2", doc.meta().label());
    // Check the search index (device2)
    let mut documents =
        device2.owner.query_map("edit", Default::default()).await?;
    assert_eq!(1, documents.len());
    let doc = documents.remove(0);
    assert_eq!("edit_2", doc.meta().label());

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
