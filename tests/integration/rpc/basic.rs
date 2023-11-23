use anyhow::Result;
use serial_test::serial;

use crate::test_utils::{server, spawn};

use sos_net::client::RpcClient;

#[tokio::test]
#[serial]
async fn integration_rpc_basic() -> Result<()> {
    //crate::test_utils::init_tracing();

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
