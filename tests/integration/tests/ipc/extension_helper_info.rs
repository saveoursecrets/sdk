use anyhow::Result;
use http::StatusCode;
use sos_ipc::{
    extension_helper::client::ExtensionHelperClient,
    local_transport::{HttpMessage, LocalRequest},
    ServiceAppInfo,
};
use sos_sdk::prelude::Paths;
use sos_test_utils::{setup, teardown};

/// Tests getting app info using a GET request to the / endpoint.
#[tokio::test]
async fn integration_ipc_extension_helper_info() -> Result<()> {
    const TEST_ID: &str = "ipc_extension_helper_info";
    // crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    Paths::scaffold(&data_dir).await?;
    let data_dir = data_dir.display().to_string();

    let request = LocalRequest::get("/".parse().unwrap());
    let (command, arguments) = super::extension_helper_cmd(&data_dir);
    let mut client = ExtensionHelperClient::new(command, arguments).await?;
    let response = client.send(request).await?;
    assert_eq!(StatusCode::OK, response.status().unwrap());
    assert_eq!(1, response.request_id());

    let info: ServiceAppInfo = serde_json::from_slice(response.body())?;
    assert_eq!("test_extension_helper", info.name);

    client.kill().await?;

    teardown(TEST_ID).await;

    Ok(())
}
