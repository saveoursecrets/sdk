use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::sdk::{prelude::*, vfs};

const TEST_ID: &str = "trusted_devices";

/// Tests adding and removing trusted devices.
#[tokio::test]
async fn integration_trusted_devices() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let (mut account, new_account) = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    let default_folder = new_account.default_folder();
    let key: AccessKey = password.clone().into();
    account.sign_in(&key).await?;
    account.open_folder(&default_folder).await?;

    let _ = account.devices()?.current_device(DeviceManager::device_info());

    // No trusted devices yet
    assert!(account.devices()?.list_trusted_devices().is_empty());

    // Add a trusted device
    let device = mock::device()?;
    account.devices_mut()?.add_device(device).await?;

    assert_eq!(1, account.devices()?.list_trusted_devices().len());

    // Sign out will lock the identity and devices vaults
    account.sign_out().await?;

    // Sign in again should load the trusted devices into memory
    account.sign_in(&key).await?;

    assert_eq!(1, account.devices()?.list_trusted_devices().len());

    // If we no longer trust a device (perhaps it was lost
    // or has been compromised) we can remove the trusted device
    let mut devices = account.devices()?.list_trusted_devices();
    let device = devices.remove(0).clone();
    account.devices_mut()?.remove_device(&device).await?;

    assert!(account.devices()?.list_trusted_devices().is_empty());

    // Check the removal persists across sign out and sign in
    account.sign_out().await?;
    account.sign_in(&key).await?;

    assert!(account.devices()?.list_trusted_devices().is_empty());

    teardown(TEST_ID).await;

    Ok(())
}
