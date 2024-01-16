use crate::test_utils::{
    assert_local_remote_events_eq, num_events, simulate_device, spawn,
    teardown,
};
use anyhow::Result;
use sos_net::{client::RemoteBridge, sdk::prelude::*};

const TEST_ID: &str = "sync_create_folder";

/// Tests sending create folder events to a remote.
#[tokio::test]
async fn integration_sync_create_folder() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare a mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let origin = device.origin.clone();
    let folders = device.folders.clone();

    let original_folders_len = folders.len();

    let (new_folder, sync_error) = device
        .owner
        .create_folder("sync_folder".to_string())
        .await?;

    assert!(sync_error.is_none());

    // Our new local folder should have the single create vault event
    assert_eq!(1, num_events(&mut device.owner, new_folder.id()).await);

    // Expected folders on the local account must be computed
    // again after creating the new folder for the assertions
    let folders: Vec<Summary> = {
        let storage = device.owner.storage().await?;
        let reader = storage.read().await;
        reader.list_folders().to_vec()
    };

    // Ensure we have the extra folder summary in memory
    assert_eq!(original_folders_len + 1, folders.len());

    // Get the remote out of the owner so we can
    // assert on equality between local and remote
    let mut provider = device.owner.delete_remote(&origin).await?.unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");

    assert_local_remote_events_eq(
        folders.clone(),
        &mut device.owner,
        remote_provider,
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}
