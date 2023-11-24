use anyhow::Result;

use sos_net::client::{RemoteBridge, RemoteSync};

use crate::test_utils::{spawn, teardown};

use super::{
    assert_local_remote_events_eq, assert_local_remote_vaults_eq,
    simulate_device, SimulatedDevice,
};

const TEST_ID: &str = "sync_rename_folder";

/// Tests sending create folder events to a remote.
#[tokio::test]
async fn integration_sync_rename_folder() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare a mock device
    let device = simulate_device(TEST_ID, &server, 1).await?;
    let SimulatedDevice {
        mut owner,
        origin,
        default_folder,
        folders,
        ..
    } = device;

    // Path that we expect the remote server to write to
    let server_path = server.account_path(owner.address());

    let sync_error = owner
        .rename_folder(&default_folder, "new_name".to_string())
        .await?;
    assert!(sync_error.is_none());

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

    assert_local_remote_events_eq(
        folders.clone(),
        &mut owner,
        remote_provider,
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}
