use super::simulate_device;
use crate::test_utils::{spawn, teardown};
use anyhow::Result;
use sos_net::client::RpcClient;
use std::time::Duration;

const TEST_ID: &str = "websocket_shutdown_signout";

/// Tests websocket shutdown logic on sign out.
#[ignore = "need to fix timeout (possible deadlock)"]
#[tokio::test]
async fn integration_websocket_shutdown_signout() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare a mock device
    let mut device = simulate_device(TEST_ID, &server, 1).await?;

    // Start the websocket connection
    device.listen().await?;

    // Wait a moment for the connection to complete
    tokio::time::sleep(Duration::from_millis(50)).await;

    let num_conns = RpcClient::num_connections(&server.origin.url).await?;
    assert_eq!(1, num_conns);

    // Sign out of the account
    device.owner.sign_out().await?;

    // Wait a moment for the connection to close
    tokio::time::sleep(Duration::from_millis(50)).await;

    let num_conns = RpcClient::num_connections(&server.origin.url).await?;
    assert_eq!(0, num_conns);

    teardown(TEST_ID).await;

    Ok(())
}
