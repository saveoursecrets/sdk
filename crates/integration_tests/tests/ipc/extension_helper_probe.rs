use anyhow::Result;
use http::StatusCode;
use sos_ipc::{
    local_transport::{HttpMessage, LocalRequest},
    extension_helper::client::NativeBridgeClient,
};
use sos_sdk::prelude::Paths;
use sos_test_utils::{setup, teardown};

/// Test checking for aliveness with a HEAD request to the / endpoint.
///
/// The extension can use this to check if it is currently connected
/// to the executable serving native messaging API requests.
#[tokio::test]
async fn integration_ipc_extension_helper_probe() -> Result<()> {
    const TEST_ID: &str = "ipc_extension_helper_probe";
    // crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    Paths::scaffold(Some(data_dir.clone())).await?;
    let data_dir = data_dir.display().to_string();

    let request = LocalRequest::head("/".parse().unwrap());
    let (command, arguments) = super::extension_helper_cmd(&data_dir);
    let mut client = NativeBridgeClient::new(command, arguments).await?;
    let response = client.send(request).await?;
    assert_eq!(StatusCode::OK, response.status().unwrap());
    assert_eq!(1, response.request_id());

    client.kill().await?;

    teardown(TEST_ID).await;

    Ok(())
}
