use anyhow::Result;
use http::StatusCode;
use sos_ipc::{
    local_transport::{HttpMessage, LocalRequest},
    native_bridge::client::NativeBridgeClient,
};

const SOCKET_NAME: &str = "ipc_native_bridge_probe.sock";

/// Test checking for aliveness by calling the /probe endpoint,
/// this endpoint is handled by the native bridge itself and does
/// not require a local server to be running.
#[tokio::test]
async fn integration_ipc_native_bridge_probe() -> Result<()> {
    // crate::test_utils::init_tracing();

    let mut request = LocalRequest::get("/probe".parse().unwrap());
    request.set_request_id(1);

    let (command, arguments) = super::native_bridge_cmd(SOCKET_NAME);
    let mut client = NativeBridgeClient::new(command, arguments).await?;
    let response = client.send(request).await?;
    assert_eq!(StatusCode::OK, response.status().unwrap());

    client.kill().await?;

    Ok(())
}
