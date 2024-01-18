use crate::test_utils::{
    assert_local_remote_events_eq, mock, num_events, simulate_device, spawn,
    teardown,
};
use anyhow::Result;
use sos_net::{client::RemoteBridge, sdk::prelude::*};

/// Tests sending update secret events to a remote.
#[tokio::test]
async fn integration_sync_update_secret() -> Result<()> {
    const TEST_ID: &str = "sync_update_secret";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare a mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let origin = device.origin.clone();
    let default_folder_id = device.default_folder_id.clone();
    let folders = device.folders.clone();

    // Create a secret
    let (meta, secret) = mock::note("note", "secret1");
    let result = device
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;
    assert!(result.sync_error.is_none());

    // Should have two events
    assert_eq!(2, num_events(&mut device.owner, &default_folder_id).await);

    let (meta, secret) = mock::note("note", "secret1");
    let SecretChange { sync_error, .. } = device
        .owner
        .update_secret(
            &result.id,
            meta,
            Some(secret),
            Default::default(),
            None,
        )
        .await?;
    assert!(sync_error.is_none());

    // Should have three events
    assert_eq!(3, num_events(&mut device.owner, &default_folder_id).await);

    // Get the remote out of the owner so we can
    // assert on equality between local and remote
    let mut provider = device.owner.remove_server(&origin).await?.unwrap();
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
