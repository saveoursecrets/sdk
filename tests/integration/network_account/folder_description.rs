use crate::test_utils::{
    assert_local_remote_events_eq, simulate_device, spawn, teardown,
};
use anyhow::Result;
use sos_net::sdk::prelude::*;

/// Tests sending create folder events to a remote.
#[tokio::test]
async fn integration_sync_folder_description() -> Result<()> {
    const TEST_ID: &str = "sync_folder_description";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare a mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let origin = device.origin.clone();
    let default_folder = device.default_folder.clone();
    let folders = device.folders.clone();

    let FolderChange { sync_error, .. } = device
        .owner
        .set_folder_description(
            &default_folder,
            "new_description".to_string(),
        )
        .await?;
    assert!(sync_error.is_none());

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
