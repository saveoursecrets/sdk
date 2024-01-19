use crate::test_utils::{
    assert_local_remote_events_eq, assert_local_remote_vaults_eq,
    simulate_device, spawn, teardown,
};
use anyhow::Result;
use sos_net::{client::RemoteBridge, sdk::prelude::*};

/// Tests creating all the account data on a remote
/// when the server does not have the account data yet.
#[tokio::test]
async fn integration_sync_create_remote_data() -> Result<()> {
    const TEST_ID: &str = "sync_create_remote_data";

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
    let mut provider = device.owner.remove_server(&origin).await?.unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");

    assert_local_remote_vaults_eq(
        folders.clone(),
        &server_path,
        &mut device.owner,
        remote_provider,
    )
    .await?;

    assert_local_remote_events_eq(
        folders,
        &mut device.owner,
        remote_provider,
    )
    .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
