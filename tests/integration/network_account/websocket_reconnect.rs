use anyhow::Result;

use std::time::Duration;

use sos_net::client::{ListenOptions, RpcClient};

use crate::test_utils::{spawn, teardown};

use super::{simulate_device, SimulatedDevice};

const TEST_ID: &str = "websocket_reconnect";

/// Tests websocket reconnect logic.
#[tokio::test]
async fn integration_websocket_reconnect() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;
    let addr = server.addr.clone();

    // Prepare a mock device
    let device = simulate_device(TEST_ID, &server, 1).await?;
    let SimulatedDevice { owner, origin, .. } = device;

    tokio::task::spawn(async move {
        // Start a websocket listener that should
        // attempt to reconnect 4 times with delays of
        // 1000ms, 2000ms, 4000ms and 8000ms before giving up.
        owner
            .listen(
                &origin,
                ListenOptions::new_config("device_1".to_string(), 500, 4)
                    .unwrap(),
            )
            .await
            .unwrap();
    });

    // Wait a little to give the websocket time to connect
    tokio::time::sleep(Duration::from_millis(10)).await;

    let num_conns = RpcClient::num_connections(&server.origin.url).await?;
    assert_eq!(1, num_conns);

    // Drop the server handle to shutdown the server
    drop(server);

    // Wait a little to give the server time to shutdown
    // and the websocket client to make re-connect attempts
    tokio::time::sleep(Duration::from_millis(5000)).await;

    // Spawn a new server so the websocket can re-connect
    let server = spawn(TEST_ID, Some(addr), None).await?;

    // Delay some more to allow the websocket to make the
    // connection
    tokio::time::sleep(Duration::from_millis(5000)).await;

    let num_conns = RpcClient::num_connections(&server.origin.url).await?;
    assert_eq!(1, num_conns);

    teardown(TEST_ID).await;

    Ok(())
}
