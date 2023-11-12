use anyhow::Result;
use serial_test::serial;

use crate::test_utils::{spawn, server};

use sos_net::{
    client::{
        net::{
            RpcClient,
        },
    },
};

#[tokio::test]
#[serial]
async fn integration_rpc_client_basic() -> Result<()> {
    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    // Check the /api route
    let server_url = server();
    let server_info = RpcClient::server_info(server_url.clone()).await?;
    assert!(server_info.status().is_success());

    // Trigger server code path for the / URL
    let response = RpcClient::get(server_url.clone()).await?;
    assert!(response.status().is_success());

    Ok(())
}
