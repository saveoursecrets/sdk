use crate::test_utils::{
    assert_local_remote_events_eq, assert_local_remote_vaults_eq,
    simulate_device, spawn, teardown,
};
use anyhow::Result;
use sos_account::Account;
use sos_protocol::{AccountSync, SyncClient};
use sos_remote_sync::RemoteSyncHandler;

/// Tests creating an account on the remote, deleting it
/// and then creating the same account again.
#[tokio::test]
async fn network_sync_recreate_account() -> Result<()> {
    const TEST_ID: &str = "sync_recreate_account";
    // crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare a mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let origin = device.origin.clone();
    let folders = device.folders.clone();
    let server_account_paths = server.paths(device.owner.account_id());

    // Get the remote out of the owner so we can
    // delete the remote account
    let bridge = device.owner.remove_server(&origin).await?.unwrap();
    // Delete the account from the remote server
    assert!(bridge.client().delete_account().await.is_ok());
    // Re-create the server on the client
    device.owner.add_server(origin.clone()).await?;
    // Sync to create the account on the remote again
    let sync_result = device.owner.sync().await;
    assert!(sync_result.first_error().is_none());

    // Now assert on the data
    let mut bridge = device.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_vaults_eq(
        folders.clone(),
        &server_account_paths,
        &mut device.owner,
    )
    .await?;
    assert_local_remote_events_eq(folders, &mut device.owner, &mut bridge)
        .await?;

    device.owner.sign_out().await?;
    teardown(TEST_ID).await;

    Ok(())
}
