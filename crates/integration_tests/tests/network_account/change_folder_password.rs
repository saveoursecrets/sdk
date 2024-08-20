use crate::test_utils::{
    assert_local_remote_events_eq, mock, simulate_device, spawn, teardown,
};
use anyhow::Result;
use sos_net::{sdk::prelude::*, AccountSync};

/// Tests changing a folder password and force syncing
/// the updated folder events log.
#[tokio::test]
#[cfg_attr(windows, ignore = "fix auto lock bug on windows (#451)")]
async fn network_sync_change_folder_password() -> Result<()> {
    const TEST_ID: &str = "sync_change_folder_password";
    // crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut device1 = simulate_device(TEST_ID, 2, Some(&server)).await?;
    let password = device1.password.clone();
    let account_key: AccessKey = password.into();
    let origin = device1.origin.clone();
    let default_folder = device1.default_folder.clone();
    let folders = device1.folders.clone();

    let mut device2 = device1.connect(1, None).await?;

    // Create a secret in the primary owner which won't exist
    // in the second device
    let (meta, secret) = mock::note(TEST_ID, TEST_ID);
    let SecretChange { id, .. } = device1
        .owner
        .create_secret(meta.clone(), secret.clone(), Default::default())
        .await?;

    // Sync on the second device to fetch initial account state
    assert!(device2.owner.sync().await.is_none());

    let (new_password, _) = generate_passphrase()?;
    let key: AccessKey = new_password.into();
    device1
        .owner
        .change_folder_password(&default_folder, key.clone())
        .await?;

    // Check we can read in the secret data after conversion
    let (secret_data, _) = device1
        .owner
        .read_secret(&id, Some(default_folder.clone()))
        .await?;
    assert_eq!(&meta, secret_data.meta());
    assert_eq!(&secret, secret_data.secret());

    // Check we can sign out and sign in again
    device1.owner.sign_out().await?;
    device1.owner.sign_in(&account_key).await?;

    // Try to sync on other device after force update
    // which should perform a force pull to update the
    // account data
    assert!(device2.owner.sync().await.is_none());

    // Check we can sign out and sign in again
    // on the device that just synced using the
    // new access key
    device2.owner.sign_in(&account_key).await?;

    // Create a secret on the synced device
    let (meta, secret) = mock::note(TEST_ID, TEST_ID);
    let SecretChange { id, .. } = device2
        .owner
        .create_secret(meta.clone(), secret.clone(), Default::default())
        .await?;

    // Sync on the original device and check it can read the secret
    assert!(device1.owner.sync().await.is_none());
    let (secret_data, _) = device1
        .owner
        .read_secret(&id, Some(default_folder.clone()))
        .await?;
    assert_eq!(&meta, secret_data.meta());
    assert_eq!(&secret, secret_data.secret());

    // Primary device should now be in sync with remote
    let mut bridge = device1.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_events_eq(
        folders.clone(),
        &mut device1.owner,
        &mut bridge,
    )
    .await?;

    // Ensure the second device is up to date with the remote
    let mut bridge = device2.owner.remove_server(&origin).await?.unwrap();
    assert_local_remote_events_eq(
        folders.clone(),
        &mut device2.owner,
        &mut bridge,
    )
    .await?;

    device1.owner.sign_out().await?;
    device2.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
