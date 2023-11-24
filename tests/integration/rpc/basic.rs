use anyhow::Result;
use serial_test::serial;

use crate::test_utils::spawn;

use sos_net::client::RpcClient;

const TEST_ID: &str = "rpc_basic";

#[tokio::test]
#[serial]
async fn integration_rpc_basic() -> Result<()> {
    //crate::test_utils::init_tracing();

    let server = spawn(None).await?;

    // Check the /api route
    let server_info = RpcClient::server_info(server.url.clone()).await?;
    assert!(server_info.status().is_success());

    // Trigger server code path for the / URL
    let response = RpcClient::get(server.url.clone()).await?;
    assert!(response.status().is_success());

    Ok(())
}
