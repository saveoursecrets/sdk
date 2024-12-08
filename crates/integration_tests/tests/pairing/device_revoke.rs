use crate::test_utils::{
    assert_local_remote_events_eq, run_pairing_protocol, simulate_device,
    spawn, teardown,
};
use anyhow::Result;
use http::StatusCode;
use sos_net::{
    protocol::{AccountSync, NetworkError},
    sdk::prelude::*,
    Error as ClientError,
};

/// Tests pairing a new device and revoking trust in the device.
#[tokio::test]
async fn pairing_device_revoke() -> Result<()> {
    const TEST_ID: &str = "pairing_device_revoke";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut primary_device =
        simulate_device(TEST_ID, 2, Some(&server)).await?;
    let origin = primary_device.origin.clone();
    let folders = primary_device.folders.clone();

    let mut enrolled_account =
        run_pairing_protocol(&mut primary_device, TEST_ID, true)
            .await?
            .unwrap();

    // Cannot revoke the current device
    let current_device_public_key = primary_device
        .owner
        .current_device()
        .await?
        .public_key()
        .clone();
    let result = primary_device
        .owner
        .revoke_device(&current_device_public_key)
        .await;
    assert!(matches!(result, Err(ClientError::RevokeDeviceSelf)));

    // Sync on the original device to fetch the updated device logs
    assert!(primary_device.owner.sync().await.first_error().is_none());

    // Primary device revokes access to the newly enrolled device
    // as if it were lost or stolen
    let device_public_key = enrolled_account.device_public_key().await?;
    primary_device
        .owner
        .revoke_device(&device_public_key)
        .await?;

    let revoke_error = enrolled_account
        .revoke_device(&current_device_public_key)
        .await;

    // println!("{:#?}", revoke_error);

    if let Err(ClientError::RevokeDeviceSync(err)) = revoke_error {
        assert!(matches!(
            &*err,
            ClientError::Network(NetworkError::ResponseJson(
                StatusCode::FORBIDDEN,
                _
            ))
        ));
    } else {
        panic!("expecting revoke device sync error");
    }

    // Attempting to sync after the device was revoked
    // yields a forbidden response
    let sync_result = enrolled_account.sync().await;
    if let Some(err) = sync_result.first_error() {
        assert!(matches!(
            err,
            ClientError::Network(NetworkError::ResponseJson(
                StatusCode::FORBIDDEN,
                _
            ))
        ));
    } else {
        panic!("expecting multiple sync error (forbidden)");
    }

    // Primary device has one trusted device (itself)
    let devices = primary_device.owner.trusted_devices().await?;
    assert_eq!(1, devices.len());

    // Check primary device is in sync with remote
    let mut bridge =
        primary_device.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_events_eq(
        folders.clone(),
        &mut primary_device.owner,
        &mut bridge,
    )
    .await?;

    primary_device.owner.sign_out().await?;
    enrolled_account.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
