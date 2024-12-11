use crate::test_utils::{simulate_device, spawn, teardown};
use anyhow::Result;
use sos_net::{
    protocol::{RemoteSyncHandler, SyncClient},
    sdk::prelude::*,
};

/// Tests creating and then deleting all the account data
/// on a remote server.
#[tokio::test]
async fn network_sync_delete_account() -> Result<()> {
    const TEST_ID: &str = "sync_delete_account";

    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare a mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let address = device.owner.address().clone();
    let origin = device.origin.clone();

    // Note that setting up the mock device automatically
    // does the initial sync to prepare the account on the
    // remote so all we need to do here is to delete the account

    // Get the remote out of the owner so we can
    // assert on equality between local and remote
    let bridge = device.owner.remove_server(&origin).await?.unwrap();
    bridge.client().delete_account(&address).await?;

    // All the local data still exists
    let local_paths = device.owner.paths();
    assert!(local_paths.user_dir().exists());
    assert!(local_paths.identity_vault().exists());
    assert!(local_paths.identity_events().exists());

    // But the server account data was removed
    let server_paths = server.paths(&address);
    assert!(!server_paths.user_dir().exists());
    assert!(!server_paths.identity_vault().exists());
    assert!(!server_paths.identity_events().exists());

    device.owner.sign_out().await?;
    teardown(TEST_ID).await;

    Ok(())
}
