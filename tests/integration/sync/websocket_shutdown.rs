use anyhow::Result;

use std::time::Duration;

use sos_net::client::ListenOptions;

use crate::test_utils::{spawn, teardown};

use super::{simulate_device, SimulatedDevice};

const TEST_ID: &str = "websocket_shutdown";

/// Tests websocket shutdown logic.
///
/// Nothing really to assert on here so in order to debug
/// enable tracing.
#[tokio::test]
async fn integration_websocket_shutdown() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare a mock device
    let device = simulate_device(TEST_ID, &server, 1).await?;

    // Start the websocket connection
    let handle = device.listen()?;

    // Wait a moment for the connection to complete
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Close the websocket connection
    handle.close();

    // Wait a moment for the connection to close
    tokio::time::sleep(Duration::from_millis(50)).await;

    teardown(TEST_ID).await;

    Ok(())
}
