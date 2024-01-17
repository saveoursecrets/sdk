use anyhow::Result;

use crate::test_utils::{
    assert_local_remote_events_eq, simulate_device, spawn, teardown,
};
use http::StatusCode;
use sos_net::{
    client::{
        Error as ClientError, NetworkAccount, RemoteBridge, RemoteSync,
        SyncError,
    },
    sdk::prelude::*,
};

const TEST_ID: &str = "device_revoke";

/// Tests enrolling a new device and revoking trust in the device.
#[tokio::test]
async fn device_revoke() -> Result<()> {
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

    // Start enrollment by fetching the account data
    // from the remote server
    let enrollment = NetworkAccount::enroll_device(
        origin.clone(),
        signing_key,
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

    // Attempting to sync after the device was revoked
    // yields a forbidden response
    let sync_error = enrolled_account.sync().await;
    if let Some(SyncError::Multiple(mut errors)) = sync_error {
        let (_, err) = errors.remove(0);
        assert!(matches!(
            err,
            ClientError::ResponseJson(StatusCode::FORBIDDEN, _)
        ));
    } else {
        panic!("expecting multiple sync error (forbidden)");
    }

    // Primary device has one trusted device (itself)
    {
        let primary_device_storage =
            primary_device.owner.storage().await.unwrap();
        let primary_device_storage = primary_device_storage.read().await;
        assert_eq!(1, primary_device_storage.devices().len());
    }

    // Check primary device is in sync with remote
    let mut provider =
        primary_device.owner.delete_remote(&origin).await?.unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");
    assert_local_remote_events_eq(
        folders.clone(),
        &mut primary_device.owner,
        remote_provider,
    )
    .await?;

    primary_device.owner.sign_out().await?;
    enrolled_account.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
