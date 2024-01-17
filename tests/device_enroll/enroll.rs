use anyhow::Result;

use crate::test_utils::{
    assert_local_remote_events_eq, mock, simulate_device, spawn, teardown,
};
use sos_net::{
    client::{NetworkAccount, RemoteBridge, RemoteSync},
    sdk::prelude::*,
};

const TEST_ID: &str = "device_enroll";

/// Tests enrolling a new device and syncing the device event log
/// including the newly enrolled device back on to a primary device.
#[tokio::test]
async fn device_enroll() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut primary_device =
        simulate_device(TEST_ID, 2, Some(&server)).await?;

    // Create a secret in the primary owner which won't exist
    // in the second device
    let (meta, secret) = mock::note(TEST_ID, TEST_ID);
    let result = primary_device
        .owner
        .create_secret(meta, secret, Default::default())
        .await?;
    assert!(result.sync_error.is_none());

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
    let enrollment =
        NetworkAccount::enroll_device(origin.clone(), signing_key, Some(data_dir))
            .await?;

    // Complete device enrollment by authenticating
    // to the new account
    let mut enrolled_account = enrollment.finish(&key).await?;

    // Sync on the original device to fetch the updated device logs
    assert!(primary_device.owner.sync().await.is_none());

    // Read the secret on the newly enrolled account
    let (secret_data, _) =
        enrolled_account.read_secret(&result.id, None).await?;
    assert_eq!(TEST_ID, secret_data.meta().label());

    // Primary device has two trusted devices
    {
        let primary_device_storage =
            primary_device.owner.storage().await.unwrap();
        let primary_device_storage = primary_device_storage.read().await;
        assert_eq!(2, primary_device_storage.devices().len());
    }

    // Enrolled device has two trusted devices
    {
        let enrolled_storage = enrolled_account.storage().await.unwrap();
        let enrolled_storage = enrolled_storage.read().await;
        assert_eq!(2, enrolled_storage.devices().len());
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

    // Check the enrolled device is in sync with remote
    let mut provider =
        enrolled_account.delete_remote(&origin).await?.unwrap();
    let remote_provider = provider
        .as_any_mut()
        .downcast_mut::<RemoteBridge>()
        .expect("to be a remote provider");
    assert_local_remote_events_eq(
        folders,
        &mut enrolled_account,
        remote_provider,
    )
    .await?;

    primary_device.owner.sign_out().await?;
    enrolled_account.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
