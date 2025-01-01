use crate::test_utils::{
    simulate_device, spawn, teardown, wait_num_websocket_connections,
};
use anyhow::Result;
use sos_account::Account;
use sos_net::protocol::network_client::{ListenOptions, NetworkRetry};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Tests websocket reconnect logic.
#[tokio::test]
async fn network_websocket_reconnect() -> Result<()> {
    const TEST_ID: &str = "websocket_reconnect";
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;
    let addr = server.addr.clone();

    // Prepare a mock device
    let device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let origin = device.origin.clone();

    let main_device = Arc::new(Mutex::new(device));
    let listen_device = Arc::clone(&main_device);

    tokio::task::spawn(async move {
        // Start a websocket listener that should
        // attempt to reconnect 4 times with delays of
        // 1000ms, 2000ms, 4000ms and 8000ms before giving up.
        let device = listen_device.lock().await;
        device
            .owner
            .listen(
                &origin,
                ListenOptions::new_retry(
                    "device_1".to_string(),
                    NetworkRetry::new(4, 500),
                )
                .unwrap(),
                None,
            )
            .await
            .unwrap();
    });

    // Wait for the connection
    wait_num_websocket_connections(&server.origin, 1).await?;

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

    // Wait for the connection
    wait_num_websocket_connections(&server.origin, 1).await?;

    let mut writer = main_device.lock().await;
    writer.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
