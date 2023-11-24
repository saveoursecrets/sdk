use anyhow::Result;

use sos_net::{
    client::{RemoteBridge, RemoteSync},
    sdk::vault::Summary,
};

use crate::test_utils::{
    create_local_account, mock_note, setup, spawn, teardown,
};

use super::{
    assert_local_remote_events_eq, num_events, simulate_device,
    SimulatedDevice,
};

const TEST_ID: &str = "sync_delete_secret";

/// Tests sending delete secret events to a remote.
#[tokio::test]
async fn integration_sync_delete_secret() -> Result<()> {
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
        server_path,
        default_folder_id,
        ..
    } = device;

    // Create a secret
    let (meta, secret) = mock_note("note", "secret1");
    let (id, sync_error) = owner
        .create_secret(meta, secret, Default::default())
        .await?;
    assert!(sync_error.is_none());

    // Should have two events
    assert_eq!(2, num_events(&mut owner, &default_folder_id).await);

    let sync_error = owner.delete_secret(&id, Default::default()).await?;
    assert!(sync_error.is_none());

    // Should have three events
    assert_eq!(3, num_events(&mut owner, &default_folder_id).await);

    // Get the remote out of the owner so we can
    // assert on equality between local and remote
    let mut provider = owner.delete_remote(&origin).unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");

    assert_local_remote_events_eq(
        folders.clone(),
        &mut owner,
        remote_provider,
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}
