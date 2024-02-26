use crate::test_utils::{
    assert_local_remote_events_eq, mock, run_pairing_protocol,
    simulate_device, spawn, teardown,
};
use anyhow::Result;
use sos_net::{client::RemoteSync, sdk::prelude::*};

/// Tests that a pending enrollment that never finishes
/// has an enrollment.json file on disc.
#[tokio::test]
async fn pairing_pending_enrollment() -> Result<()> {
    const TEST_ID: &str = "pairing_pending_enrollment";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut primary_device =
        simulate_device(TEST_ID, 2, Some(&server)).await?;
    let origin = primary_device.origin.clone();
    let folders = primary_device.folders.clone();

    // Create a secret in the primary owner which won't exist
    // in the second device
    let (meta, secret) = mock::note(TEST_ID, TEST_ID);
    let result = primary_device
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;
    assert!(result.sync_error.is_none());

    // Run the pairing protocol to completion.
    run_pairing_protocol(&mut primary_device, TEST_ID, false).await?;

    // Data directory of the connecting device
    let data_dir = primary_device.dirs.clients.get(1).cloned().unwrap();
    let paths =
        Paths::new(data_dir, primary_device.owner.address().to_string());
    let enrollment_file = paths.enrollment();
    assert!(vfs::try_exists(enrollment_file).await?);

    primary_device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
