use super::simulate_device;
use crate::test_utils::{spawn, teardown};
use anyhow::Result;
use sos_net::client::{RemoteBridge, RpcClient};
use std::time::Duration;

const TEST_ID: &str = "websocket_shutdown";

/// Tests websocket shutdown logic.
#[tokio::test]
async fn integration_websocket_shutdown() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare a mock device
    let device = simulate_device(TEST_ID, &server, 1).await?;

    // Start the websocket connection
    let handle = device.listen().await?;

    // Wait a moment for the connection to complete
    tokio::time::sleep(Duration::from_millis(50)).await;

    let num_conns = RpcClient::num_connections(&server.origin.url).await?;
    assert_eq!(1, num_conns);

    // Close the websocket connection
    handle.close();

    // Wait a moment for the connection to close
    tokio::time::sleep(Duration::from_millis(50)).await;

    let num_conns = RpcClient::num_connections(&server.origin.url).await?;
    assert_eq!(0, num_conns);

    teardown(TEST_ID).await;

    Ok(())
}
