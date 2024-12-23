use crate::test_utils::{
    assert_local_remote_events_eq, mock, simulate_device, spawn, sync_pause,
    teardown,
};
use anyhow::Result;
use sos_net::{protocol::AccountSync, sdk::prelude::*};

/// Tests making deletes to a folder whilst
/// a server is offline and resolving the conflicts with
/// an auto merge.
#[tokio::test]
async fn auto_merge_delete_secrets() -> Result<()> {
    const TEST_ID: &str = "auto_merge_delete_secrets";
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

    // Create a secret (device1)
    let (meta, secret) = mock::note("note_1", TEST_ID);
    let result1 = device1
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;
    assert!(result1.sync_result.first_error().is_none());

    // Create a secret (device2) which will auto merge
    //
    // After this, the first client will have one secret and the
    // second client and the server will have them both as the
    // automatic sync on secret creation will merge the secret
    // from device1
    let (meta, secret) = mock::note("note_2", TEST_ID);
    let result2 = device2
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;
    assert!(result2.sync_result.first_error().is_none());

    // Oh no, the server has gone offline!
    drop(server);
    // Wait a while to make sure the server has gone
    sync_pause(None).await;

    // First device deletes it's secret
    let result = device1
        .owner
        .delete_secret(&result1.id, Default::default())
        .await?;
    assert!(result.sync_result.first_error().is_some());

    // Second device deletes it's secret
    let result = device2
        .owner
        .delete_secret(&result2.id, Default::default())
        .await?;
    assert!(result.sync_result.first_error().is_some());

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

    // Sync first device for another auto merge
    //
    // This brings the first client and server into sync
    // with both create secrets and the deletion on the
    // first client but the second client is out of sync.
    assert!(device1.owner.sync().await.first_error().is_none());

    // Sync second device to auto merge and push their offline changes
    assert!(device2.owner.sync().await.first_error().is_none());

    // Sync first device again to fetch the pushed changes
    assert!(device1.owner.sync().await.first_error().is_none());

    // Folder commits are back in sync
    let device1_folder_state =
        device1.owner.commit_state(&default_folder).await?;
    let device2_folder_state =
        device2.owner.commit_state(&default_folder).await?;

    assert_eq!(device1_folder_state, device2_folder_state);

    // Make sure both devices can't see either secret
    device1
        .owner
        .read_secret(&result1.id, None)
        .await
        .err()
        .unwrap()
        .is_secret_not_found();
    device1
        .owner
        .read_secret(&result2.id, None)
        .await
        .err()
        .unwrap()
        .is_secret_not_found();

    device2
        .owner
        .read_secret(&result1.id, None)
        .await
        .err()
        .unwrap()
        .is_secret_not_found();
    device2
        .owner
        .read_secret(&result2.id, None)
        .await
        .err()
        .unwrap()
        .is_secret_not_found();

    // Check the search index (device1)
    let documents =
        device1.owner.query_map("note", Default::default()).await?;
    assert_eq!(0, documents.len());
    // Check the search index (device2)
    let documents =
        device2.owner.query_map("note", Default::default()).await?;
    assert_eq!(0, documents.len());

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
