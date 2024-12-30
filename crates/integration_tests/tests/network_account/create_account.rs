use crate::test_utils::{
    assert_local_remote_events_eq, assert_local_remote_vaults_eq,
    simulate_device, spawn, teardown,
};
use anyhow::Result;
use sos_account::Account;

/// Tests creating all the account data on a remote
/// when the server does not have the account data yet.
#[tokio::test]
async fn network_sync_create_account() -> Result<()> {
    const TEST_ID: &str = "sync_create_account";

    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare a mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let origin = device.origin.clone();
    let server_path = device.server_path.clone();
    let folders = device.folders.clone();

    // Note that setting up the mock device automatically
    // does the initial sync to prepare the account on the
    // remote so all we need to do here is to assert

    // Get the remote out of the owner so we can
    // assert on equality between local and remote
    let mut bridge = device.owner.remove_server(&origin).await?.unwrap();

    assert_local_remote_vaults_eq(
        folders.clone(),
        &server_path,
        &mut device.owner,
        &mut bridge,
    )
    .await?;

    assert_local_remote_events_eq(folders, &mut device.owner, &mut bridge)
        .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
