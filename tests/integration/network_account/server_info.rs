use crate::test_utils::{spawn, teardown};
use anyhow::Result;
use sos_net::client::HttpClient;

#[tokio::test]
async fn integration_server_info() -> Result<()> {
    const TEST_ID: &str = "server_info";
    //crate::test_utils::init_tracing();

    let server = spawn(TEST_ID, None, None).await?;

    // Check the /api route
    let server_info = HttpClient::server_info(server.url.clone()).await?;
    assert!(!server_info.name.is_empty());
    assert!(!server_info.version.is_empty());

    teardown(TEST_ID).await;

    Ok(())
}
