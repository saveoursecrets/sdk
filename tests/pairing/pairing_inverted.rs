use crate::test_utils::{
    assert_local_remote_events_eq, mock, run_inverted_pairing_protocol,
    simulate_device, spawn, teardown,
};
use anyhow::Result;
use sos_net::{sdk::prelude::*, RemoteSync};

/// Tests the protocol for pairing devices using the inverted flow.
#[tokio::test]
async fn pairing_inverted() -> Result<()> {
    const TEST_ID: &str = "pairing_inverted";
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
    let mut enrolled_account =
        run_inverted_pairing_protocol(&mut primary_device, TEST_ID).await?;

    // Sync on the original device to fetch the updated device logs
    assert!(primary_device.owner.sync().await.is_none());

    // Read the secret on the newly enrolled account
    let (secret_data, _) =
        enrolled_account.read_secret(&result.id, None).await?;
    assert_eq!(TEST_ID, secret_data.meta().label());

    // Primary device has two trusted devices
    let devices = primary_device.owner.trusted_devices().await?;
    assert_eq!(2, devices.len());

    // Enrolled device has two trusted devices
    let devices = enrolled_account.trusted_devices().await?;
    assert_eq!(2, devices.len());

    // Check primary device is in sync with remote
    let mut bridge =
        primary_device.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_events_eq(
        folders.clone(),
        &mut primary_device.owner,
        &mut bridge,
    )
    .await?;

    // Check the enrolled device is in sync with remote
    let mut bridge = enrolled_account.remove_server(&origin).await?.unwrap();
    assert_local_remote_events_eq(
        folders,
        &mut enrolled_account,
        &mut bridge,
    )
    .await?;

    // Sign out all devices
    primary_device.owner.sign_out().await?;
    enrolled_account.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
