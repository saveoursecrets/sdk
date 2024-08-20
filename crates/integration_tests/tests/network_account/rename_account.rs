use crate::test_utils::{
    assert_local_remote_events_eq, simulate_device, spawn, teardown,
};
use anyhow::Result;
use sos_net::{sdk::prelude::*, AccountSync};

/// Tests changing the account name is synced.
#[tokio::test]
async fn network_sync_rename_account() -> Result<()> {
    const TEST_ID: &str = "sync_rename_account";
    // crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock devices
    let mut device1 = simulate_device(TEST_ID, 2, Some(&server)).await?;
    let origin = device1.origin.clone();
    let folders = device1.folders.clone();

    let mut device2 = device1.connect(1, None).await?;

    let account_name = "new_account_name";

    let device1_name = {
        let data = device1.owner.account_data().await?;
        data.account.label().to_string()
    };
    let device2_name = {
        let data = device2.owner.account_data().await?;
        data.account.label().to_string()
    };
    assert_eq!(device1_name, device2_name);

    // Rename the account
    device1
        .owner
        .rename_account(account_name.to_owned())
        .await?;

    // Now the names are out of sync
    let device1_name = {
        let data = device1.owner.account_data().await?;
        data.account.label().to_string()
    };
    let device2_name = {
        let data = device2.owner.account_data().await?;
        data.account.label().to_string()
    };
    assert_ne!(device1_name, device2_name);

    // Sync on the other device
    assert!(device2.owner.sync().await.is_none());

    // Now the names are back in sync
    let device1_name = {
        let data = device1.owner.account_data().await?;
        data.account.label().to_string()
    };
    let device2_name = {
        let data = device2.owner.account_data().await?;
        data.account.label().to_string()
    };
    assert_eq!(device1_name, device2_name);

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
