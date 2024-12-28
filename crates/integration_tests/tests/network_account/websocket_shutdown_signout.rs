use crate::test_utils::{
    simulate_device, spawn, teardown, wait_num_websocket_connections,
};
use anyhow::Result;
use sos_net::sdk::prelude::*;

/// Tests websocket shutdown logic on sign out.
#[tokio::test]
async fn network_websocket_shutdown_signout() -> Result<()> {
    const TEST_ID: &str = "websocket_shutdown_signout";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare a mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;

    // Start the websocket connection
    device.listen().await?;

    wait_num_websocket_connections(&server.origin, 1).await?;

    // Sign out of the account
    device.owner.sign_out().await?;

    wait_num_websocket_connections(&server.origin, 0).await?;

    teardown(TEST_ID).await;

    Ok(())
}
