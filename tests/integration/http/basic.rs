use crate::test_utils::{spawn, teardown};
use anyhow::Result;
use sos_net::client::HttpClient;

const TEST_ID: &str = "http_basic";

#[tokio::test]
async fn integration_http_basic() -> Result<()> {
    //crate::test_utils::init_tracing();

    let server = spawn(TEST_ID, None, None).await?;

    // Check the /api route
    let server_info = HttpClient::server_info(server.url.clone()).await?;
    assert!(server_info.status().is_success());

    // Trigger server code path for the / URL
    let response = HttpClient::get(server.url.clone()).await?;
    assert!(response.status().is_success());

    teardown(TEST_ID).await;

    Ok(())
}
