use crate::test_utils::{
    assert_local_remote_events_eq, num_events, simulate_device, spawn,
    teardown,
};
use anyhow::Result;
use sos_account::{Account, FolderCreate};
use sos_client_storage::NewFolderOptions;
use sos_sdk::prelude::*;

/// Tests sending create folder events to a remote.
#[tokio::test]
async fn network_sync_folder_create() -> Result<()> {
    const TEST_ID: &str = "sync_folder_create";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare a mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let origin = device.origin.clone();
    let folders = device.folders.clone();

    let original_folders_len = folders.len();

    let FolderCreate {
        folder: new_folder,
        sync_result,
        ..
    } = device
        .owner
        .create_folder(NewFolderOptions::new("sync_folder".to_string()))
        .await?;

    assert!(sync_result.first_error().is_none());

    // Our new local folder should have the single create vault event
    assert_eq!(1, num_events(&mut device.owner, new_folder.id()).await);

    // Expected folders on the local account must be computed
    // again after creating the new folder for the assertions
    let folders: Vec<Summary> = device.owner.list_folders().await?;

    // Ensure we have the extra folder summary in memory
    assert_eq!(original_folders_len + 1, folders.len());

    // Get the remote out of the owner so we can
    // assert on equality between local and remote
    let mut bridge = device.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_events_eq(
        folders.clone(),
        &mut device.owner,
        &mut bridge,
    )
    .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
