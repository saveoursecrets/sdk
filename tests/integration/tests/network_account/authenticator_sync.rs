use crate::test_utils::{mock, simulate_device, spawn, teardown};
use anyhow::Result;
use sos_account::{Account, FolderCreate, SecretChange};
use sos_client_storage::NewFolderOptions;
use sos_protocol::AccountSync;
use sos_sdk::prelude::*;

/// Tests syncing an authenticator folder after
/// disabling the NO_SYNC flag.
#[tokio::test]
async fn network_authenticator_sync() -> Result<()> {
    const TEST_ID: &str = "authenticator_sync";
    // crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut desktop = simulate_device(TEST_ID, 2, Some(&server)).await?;
    let mut mobile = desktop.connect(1, None).await?;

    // Create folder with AUTHENTICATOR | LOCAL | NO_SYNC flags
    let options = NewFolderOptions {
        name: TEST_ID.to_owned(),
        flags: Some(
            VaultFlags::AUTHENTICATOR
                | VaultFlags::LOCAL
                | VaultFlags::NO_SYNC,
        ),
        ..Default::default()
    };
    let FolderCreate { folder, .. } =
        mobile.owner.create_folder(options).await?;

    // Create a TOTP secret in the new authenticator folder
    let (meta, secret) = mock::totp(TEST_ID);
    let SecretChange { id, .. } = mobile
        .owner
        .create_secret(meta, secret, folder.id().into())
        .await?;

    // Desktop syncs before NO_SYNC flag has been removed
    let sync_result = desktop.owner.sync().await;
    assert!(sync_result.first_error().is_none());

    // Try to read the secret but can't as the server
    // will not send events when NO_SYNC is set
    assert!(desktop
        .owner
        .read_secret(&id, Some(folder.id()))
        .await
        .is_err());

    // Update the folder with new flags so it can be synced
    mobile
        .owner
        .update_folder_flags(
            folder.id(),
            VaultFlags::AUTHENTICATOR | VaultFlags::LOCAL,
        )
        .await?;

    // Sync the account on the desktop device
    let sync_result = desktop.owner.sync().await;
    assert!(sync_result.first_error().is_none());

    // Should be able to read the TOTP on the synced desktop device
    let (data, _) = desktop.owner.read_secret(&id, Some(folder.id())).await?;
    assert_eq!(TEST_ID, data.meta().label());

    // Desktop now has an auth folder
    let auth_folder = desktop.owner.authenticator_folder().await;
    assert!(auth_folder.is_some());

    // Auth folder flags should be updated and correct
    let auth_folder = auth_folder.unwrap();
    assert!(auth_folder.flags().is_authenticator());
    assert!(!auth_folder.flags().is_sync_disabled());

    desktop.owner.sign_out().await?;
    mobile.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
