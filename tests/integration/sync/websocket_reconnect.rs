use anyhow::Result;
use copy_dir::copy_dir;
use std::{path::PathBuf, sync::Arc, time::Duration};

use sos_net::{
    client::{ListenOptions, RemoteBridge, RemoteSync, UserStorage},
    sdk::vault::Summary,
};

use crate::test_utils::{
    create_local_account, mock_note, setup, spawn, teardown,
};

use super::{
    assert_local_remote_events_eq, num_events, simulate_device,
    SimulatedDevice,
};

const TEST_ID: &str = "websocket_reconnect";

/// Tests websocket reconnect logic.
///
/// Nothing really to assert on here so in order to debug
/// enable tracing.
#[tokio::test]
async fn integration_websocket_reconnect() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare a mock device
    let device = simulate_device(TEST_ID, &server, 1).await?;
    let SimulatedDevice {
        mut owner, origin, ..
    } = device;

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
            .unwrap();
    });

    // Wait a little to give the websocket time to connect
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Drop the server handle to shutdown the server
    drop(server);

    // Wait a little to give the server time to shutdown
    // and the websocket client to make re-connect attempts
    tokio::time::sleep(Duration::from_millis(5000)).await;

    // Spawn a new server so the websocket can re-connect
    let _server = spawn(TEST_ID, None, None).await?;

    // Delay some more to allow the websocket to make the
    // connection
    tokio::time::sleep(Duration::from_millis(5000)).await;

    teardown(TEST_ID).await;

    Ok(())
}
