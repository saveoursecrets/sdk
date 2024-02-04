use anyhow::Result;

use crate::test_utils::{
    assert_local_remote_events_eq, simulate_device, spawn, teardown,
};
use http::StatusCode;
use sos_net::{
    client::{Error as ClientError, NetworkAccount, RemoteSync, SyncError},
    sdk::prelude::*,
};

/// Tests enrolling a new device and revoking trust in the device.
#[tokio::test]
async fn device_revoke() -> Result<()> {
    const TEST_ID: &str = "device_revoke";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut primary_device =
        simulate_device(TEST_ID, 2, Some(&server)).await?;

    let password = primary_device.password.clone();
    let key: AccessKey = password.into();
    let origin = primary_device.origin.clone();
    let signing_key = primary_device.owner.account_signer().await?;
    let data_dir = primary_device.dirs.clients.get(1).cloned().unwrap();
    let folders = primary_device.folders.clone();

    // Need to clear the data directory for the second client
    // as simulate_device() copies all the account data and
    // the identity folder must not exist to enroll a new device
    std::fs::remove_dir_all(&data_dir)?;
    std::fs::create_dir(&data_dir)?;

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

    // Start enrollment by fetching the account data
    // from the remote server
    let enrollment = NetworkAccount::enroll_device(
        origin.clone(),
        signing_key,
        DeviceSigner::new_random(),
        Some(data_dir),
    )
    .await?;

    // Complete device enrollment by authenticating
    // to the new account
    let mut enrolled_account = enrollment.finish(&key).await?;

    // Sync on the original device to fetch the updated device logs
    assert!(primary_device.owner.sync().await.is_none());

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

    if let Err(ClientError::RevokeDeviceSync(mut e)) = revoke_error {
        let (_, err) = e.errors.remove(0);
        assert!(matches!(
            err,
            ClientError::ResponseJson(StatusCode::FORBIDDEN, _)
        ));
    } else {
        panic!("expecting revoke device sync error");
    }

    // Attempting to sync after the device was revoked
    // yields a forbidden response
    let sync_error = enrolled_account.sync().await;
    if let Some(SyncError { mut errors }) = sync_error {
        let (_, err) = errors.remove(0);
        assert!(matches!(
            err,
            ClientError::ResponseJson(StatusCode::FORBIDDEN, _)
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
