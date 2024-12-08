use crate::test_utils::{
    assert_local_remote_events_eq, mock, simulate_device, spawn, teardown,
};
use anyhow::Result;
use sos_net::{protocol::AccountSync, sdk::prelude::*};

/// Tests changing the account cipher and force syncing
/// the updated and diverged account data.
#[tokio::test]
#[cfg_attr(windows, ignore = "fix auto lock bug on windows (#451)")]
async fn network_sync_change_cipher() -> Result<()> {
    const TEST_ID: &str = "sync_change_cipher";
    // crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut device1 = simulate_device(TEST_ID, 2, Some(&server)).await?;
    let origin = device1.origin.clone();
    let key: AccessKey = device1.password.clone().into();
    let default_folder = device1.default_folder.clone();
    let original_folders = device1.folders.clone();
    let identity_summary = device1.owner.identity_folder_summary().await?;
    let cipher = identity_summary.cipher();
    assert_eq!(cipher, &Cipher::default());

    let mut device2 = device1.connect(1, None).await?;

    // Create a secret in the primary owner which won't exist
    // in the second device
    let (meta, secret) = mock::note(TEST_ID, TEST_ID);
    let SecretChange { id, .. } = device1
        .owner
        .create_secret(meta.clone(), secret.clone(), Default::default())
        .await?;

    // Sync on the second device to fetch initial account state
    assert!(device2.owner.sync().await.first_error().is_none());

    let target_cipher = Cipher::XChaCha20Poly1305;
    let target_kdf = KeyDerivation::BalloonHash;
    let conversion = device1
        .owner
        .change_cipher(&key, &target_cipher, Some(target_kdf))
        .await?;
    assert!(!conversion.is_empty());

    // Check in-memory folders report correct target cipher
    let folders = device1.owner.list_folders().await?;
    assert!(folders.len() > 0);
    assert_eq!(original_folders.len(), folders.len());
    for folder in &folders {
        assert_eq!(&target_cipher, folder.cipher());
        assert_eq!(&target_kdf, folder.kdf());
    }

    // Check we can read in the secret data after conversion
    let (secret_data, _) = device1
        .owner
        .read_secret(&id, Some(default_folder.clone()))
        .await?;
    assert_eq!(&meta, secret_data.meta());
    assert_eq!(&secret, secret_data.secret());

    // Check the in-memory identity summary is correct cipher/kdf
    let identity_summary = device1.owner.identity_folder_summary().await?;
    assert_eq!(&target_cipher, identity_summary.cipher());
    assert_eq!(&target_kdf, identity_summary.kdf());

    // Check we can sign out and sign in again
    device1.owner.sign_out().await?;
    device1.owner.sign_in(&key).await?;

    // Folder is out of sync
    let device1_commit = device1.owner.root_commit(&default_folder).await?;
    let device2_commit = device2.owner.root_commit(&default_folder).await?;
    assert_ne!(device1_commit, device2_commit);

    // Try to sync on other device after force update
    // which should perform a force pull to update the
    // account data
    assert!(device2.owner.sync().await.first_error().is_none());

    // Check we can sign in again
    device2.owner.sign_in(&key).await?;

    // Folder is back in sync
    let device1_commit = device1.owner.root_commit(&default_folder).await?;
    let device2_commit = device2.owner.root_commit(&default_folder).await?;
    assert_eq!(device1_commit, device2_commit);

    // Create a secret on the synced device
    let (meta, secret) = mock::note(TEST_ID, TEST_ID);
    let SecretChange {
        id, sync_result, ..
    } = device2
        .owner
        .create_secret(meta.clone(), secret.clone(), Default::default())
        .await?;
    assert!(sync_result.first_error().is_none());

    // Sync on the original device and check it can read the secret
    assert!(device1.owner.sync().await.first_error().is_none());

    let device1_commit = device1.owner.root_commit(&default_folder).await?;
    let device2_commit = device2.owner.root_commit(&default_folder).await?;
    assert_eq!(device1_commit, device2_commit);

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
