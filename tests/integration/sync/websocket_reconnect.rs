use anyhow::Result;
use copy_dir::copy_dir;
use serial_test::serial;
use std::{path::PathBuf, sync::Arc, time::Duration};

use sos_net::{
    client::{ListenOptions, RemoteBridge, RemoteSync, UserStorage},
    sdk::vault::Summary,
};

use crate::test_utils::{
    create_local_account, mock_note, origin, setup, spawn,
};

use super::{assert_local_remote_events_eq, num_events};

/// Tests websocket reconnect logic.
#[tokio::test]
#[serial]
async fn integration_websocket_reconnect() -> Result<()> {
    //crate::test_utils::init_tracing();

    // Prepare distinct data directories for the two clients
    let dirs = setup(1).await?;

    // Set up the paths for the first client
    let test_data_dir = dirs.clients.get(0).unwrap();

    // Spawn a backend server and wait for it to be listening
    let (rx, handle) = spawn()?;
    let _ = rx.await?;

    let (mut owner, _, _, _) = create_local_account(
        "sync_websocket_reconnect",
        Some(test_data_dir.clone()),
    )
    .await?;

    // Create the remote provider
    let origin = origin();
    let provider = owner.remote_bridge(&origin).await?;
    owner.insert_remote(origin.clone(), Box::new(provider));

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
    drop(handle);

    // Wait a little to give the server time to shutdown
    // and the websocket client to make re-connect attempts
    tokio::time::sleep(Duration::from_millis(5000)).await;

    // Spawn a new server so the websocket can re-connect
    let (rx, handle) = spawn()?;
    let _ = rx.await?;

    // Delay some more to allow the websocket to make the
    // connection
    tokio::time::sleep(Duration::from_millis(5000)).await;

    Ok(())
}
