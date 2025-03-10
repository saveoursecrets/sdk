use crate::test_utils::{simulate_device, spawn, teardown};
use anyhow::Result;
use sos_account::Account;
use sos_sdk::prelude::*;

/// Tests the logic for saving and loading remote definitions.
#[tokio::test]
async fn network_sync_server_definitions() -> Result<()> {
    const TEST_ID: &str = "server_definitions";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare a mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;

    // Test server is configured as the remote
    let servers = device.owner.servers().await;
    assert_eq!(1, servers.len());

    device.owner.sign_out().await?;

    // Signing out deletes all the remotes
    let servers = device.owner.servers().await;
    assert_eq!(0, servers.len());

    // Sign in to load the remote definitions from disc
    let key: AccessKey = device.password.clone().into();
    device.owner.sign_in(&key).await?;

    // The servers config should be loaded
    let servers = device.owner.servers().await;
    assert_eq!(1, servers.len());

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
