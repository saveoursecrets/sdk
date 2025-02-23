use anyhow::Result;
use sos_account::LocalAccountSwitcher;
use sos_ipc::{
    local_transport::{HttpMessage, LocalRequest},
    memory_server::LocalMemoryServer,
    ServiceAppInfo, WebAccounts,
};
use sos_sdk::Paths;
use sos_test_utils::teardown;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::test_utils::setup;

/// Test the in-memory HTTP server in isolation outside
/// of the context of the native bridge code.
///
/// Runs a simple GET request and basic concurrency test
/// making multiple simultaneous requests.
#[tokio::test]
async fn integration_ipc_memory_server() -> Result<()> {
    const TEST_ID: &str = "ipc_memory_server";
    // crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    Paths::scaffold(Some(data_dir.clone())).await?;
    let paths = Paths::new_client(data_dir.clone());

    // Setup empty accounts
    let accounts = LocalAccountSwitcher::from(paths);
    let ipc_accounts = Arc::new(RwLock::new(accounts));

    let name = "mock-service";
    let version = "1.0.0";

    let app_info = ServiceAppInfo {
        name: name.to_string(),
        version: version.to_string(),
    };

    let client = LocalMemoryServer::listen(
        WebAccounts::new(ipc_accounts),
        app_info.clone(),
    )
    .await?;
    let request = LocalRequest::get("/".parse().unwrap());
    let response = client.send(request).await?;
    let result: ServiceAppInfo = serde_json::from_slice(response.body())?;
    assert_eq!(app_info, result);

    let mut futures = Vec::new();
    for _ in 0..100 {
        let client = client.clone();
        futures.push(Box::pin(async move {
            let request = LocalRequest::get("/".parse().unwrap());
            let response = client.send(request).await?;
            let result: ServiceAppInfo =
                serde_json::from_slice(response.body())?;
            Ok::<_, anyhow::Error>(result)
        }));
    }

    let results = futures::future::try_join_all(futures).await?;
    for res in results {
        assert_eq!(app_info, res);
    }

    teardown(TEST_ID).await;

    Ok(())
}
