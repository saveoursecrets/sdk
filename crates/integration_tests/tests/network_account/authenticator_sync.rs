use crate::test_utils::{mock, simulate_device, spawn, teardown};
use anyhow::Result;
use sos_net::{
    protocol::SyncStorage, sdk::prelude::*, NetworkAccount, RemoteSync,
    SyncClient,
};

/// Tests syncing an authenticator folder after disabling the NO_SYNC flag.
#[tokio::test]
async fn network_authenticator_sync() -> Result<()> {
    const TEST_ID: &str = "authenticator_sync";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, Some(TEST_ID)).await?;
    let origin = server.origin.clone();

    // Prepare mock devices
    let mut desktop = simulate_device(TEST_ID, 2, Some(&server)).await?;
    let mut mobile = desktop.connect(1, None).await?;

    // Create folder with AUTHENTICATOR | NO_SYNC flags
    let options = NewFolderOptions {
        flags: VaultFlags::AUTHENTICATOR | VaultFlags::NO_SYNC,
        ..Default::default()
    };
    let FolderCreate { folder, .. } = mobile
        .owner
        .create_folder(TEST_ID.to_owned(), options)
        .await?;

    println!("auth_folder_id: {}", folder.id());

    // Sync the account to push the new folder
    assert!(mobile.owner.sync().await.is_none());

    // Create a TOTP secret in the new authenticator folder
    let (meta, secret) = mock::totp(TEST_ID);
    let SecretChange { id, .. } = mobile
        .owner
        .create_secret(meta, secret, folder.clone().into())
        .await?;

    // Update the folder with new flags so it can be synced
    mobile
        .owner
        .update_folder_flags(&folder, VaultFlags::AUTHENTICATOR)
        .await?;

    // Sync the account on the desktop device
    assert!(desktop.owner.sync().await.is_none());

    // Should be able to read the TOTP on the synced desktop device
    let (data, _) =
        desktop.owner.read_secret(&id, Some(folder.clone())).await?;
    assert_eq!(TEST_ID, data.meta().label());

    let auth_folder = desktop.owner.authenticator_folder().await;
    println!("{:#?}", auth_folder);

    desktop.owner.sign_out().await?;
    mobile.owner.sign_out().await?;

    // teardown(TEST_ID).await;

    Ok(())
}
