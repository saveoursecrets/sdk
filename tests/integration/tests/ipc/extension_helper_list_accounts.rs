use anyhow::Result;
use http::StatusCode;
use sos_account::LocalAccount;
use sos_ipc::{
    extension_helper::client::ExtensionHelperClient,
    local_transport::{HttpMessage, LocalRequest},
};
use sos_sdk::prelude::{generate_passphrase, Paths, PublicIdentity};

use sos_test_utils::{make_client_backend, setup, teardown};

/// Test listing accounts via the native bridge when there
/// are no accounts present.
#[tokio::test]
async fn integration_ipc_extension_helper_list_accounts_empty() -> Result<()>
{
    const TEST_ID: &str = "ipc_extension_helper_list_accounts_empty";
    // crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    Paths::scaffold(Some(data_dir.clone())).await?;
    let data_dir = data_dir.display().to_string();

    let request = LocalRequest::get("/accounts".parse().unwrap());

    let (command, arguments) = super::extension_helper_cmd(&data_dir);
    let mut client = ExtensionHelperClient::new(command, arguments).await?;
    let response = client.send(request).await?;
    assert_eq!(StatusCode::OK, response.status().unwrap());
    assert_eq!(1, response.request_id());
    assert!(response.is_json());

    // No accounts configured for this test spec
    let accounts: Vec<PublicIdentity> =
        serde_json::from_slice(response.body())?;
    assert_eq!(0, accounts.len());

    client.kill().await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Test listing accounts via the native bridge.
#[tokio::test]
async fn integration_ipc_extension_helper_list_accounts() -> Result<()> {
    const TEST_ID: &str = "ipc_extension_helper_list_accounts";
    // crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    Paths::scaffold(Some(data_dir.clone())).await?;
    let paths = Paths::new_global(&data_dir);

    let (password, _) = generate_passphrase()?;
    let _account = LocalAccount::new_account(
        TEST_ID.to_string(),
        password,
        make_client_backend(&paths).await?,
    )
    .await?;

    let request = LocalRequest::get("/accounts".parse().unwrap());

    let data_dir = data_dir.display().to_string();
    let (command, arguments) = super::extension_helper_cmd(&data_dir);
    let mut client = ExtensionHelperClient::new(command, arguments).await?;
    let response = client.send(request).await?;
    assert_eq!(StatusCode::OK, response.status().unwrap());
    assert_eq!(1, response.request_id());
    assert!(response.is_json());

    // Single account configured for this test spec
    let accounts: Vec<PublicIdentity> =
        serde_json::from_slice(response.body())?;
    assert_eq!(1, accounts.len());

    client.kill().await?;

    teardown(TEST_ID).await;

    Ok(())
}
