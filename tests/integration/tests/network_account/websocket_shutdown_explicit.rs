use anyhow::Result;
use sos_account::Account;
use sos_test_utils::{
    simulate_device, spawn, teardown, wait_num_websocket_connections,
};

/// Tests websocket shutdown logic.
#[tokio::test]
async fn network_websocket_shutdown_explicit() -> Result<()> {
    const TEST_ID: &str = "websocket_shutdown_explicit";

    // sos_test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;
    let origin = server.origin.clone();

    // Prepare a mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;

    // Start the websocket connection
    device.listen().await?;

    wait_num_websocket_connections(&server.origin, 1).await?;

    // Close the websocket connection
    device.owner.stop_listening(&origin).await;

    wait_num_websocket_connections(&server.origin, 0).await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
