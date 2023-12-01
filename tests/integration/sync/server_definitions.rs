use anyhow::Result;
use crate::test_utils::{spawn, teardown};
use super::{
    simulate_device,
};

const TEST_ID: &str = "server_definitions";

/// Tests the logic for saving and loading remote definitions.
#[tokio::test]
async fn integration_sync_server_definitions() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare a mock device
    let mut device = simulate_device(TEST_ID, &server, 1).await?;
    
    // Test server is configured as the remote
    let servers = device.owner.servers().await;
    assert_eq!(1, servers.len());

    device.owner.sign_out().await?;
    
    // Signing out deletes all the remotes
    let servers = device.owner.servers().await;
    assert_eq!(0, servers.len());
    
    // Sign in to load the remote definitions from disc
    device.owner.sign_in(device.password.clone()).await?;
    
    // The servers config should be loaded
    let servers = device.owner.servers().await;
    assert_eq!(1, servers.len());

    teardown(TEST_ID).await;

    Ok(())
}
