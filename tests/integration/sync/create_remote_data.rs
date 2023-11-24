use anyhow::Result;

use sos_net::client::{RemoteBridge, RemoteSync};

use crate::test_utils::{spawn, teardown};

use super::{
    assert_local_remote_events_eq, assert_local_remote_vaults_eq,
    simulate_device, SimulatedDevice,
};

const TEST_ID: &str = "sync_create_remote_data";

/// Tests creating all the account data on a remote
/// when the server does not have the account data yet.
#[tokio::test]
async fn integration_sync_create_remote_data() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare a mock device
    let device = simulate_device(TEST_ID, &server, 1).await?;
    let SimulatedDevice {
        mut owner,
        origin,

        server_path,
        folders,
        ..
    } = device;

    // Note that setting up the mock device automatically
    // does the initial sync to prepare the account on the
    // remote so all we need to do here is to assert

    // Get the remote out of the owner so we can
    // assert on equality between local and remote
    let mut provider = owner.delete_remote(&origin).unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");

    assert_local_remote_vaults_eq(
        folders.clone(),
        &server_path,
        &mut owner,
        remote_provider,
    )
    .await?;

    assert_local_remote_events_eq(folders, &mut owner, remote_provider)
        .await?;

    teardown(TEST_ID).await;

    Ok(())
}
