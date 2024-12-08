use anyhow::Result;
use sos_ipc::{memory::LocalMemoryServer, ServiceAppInfo};
use sos_net::sdk::{prelude::LocalAccountSwitcher, Paths};
use sos_test_utils::teardown;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::test_utils::setup;

#[tokio::test]
async fn integration_ipc_memory_server() -> Result<()> {
    const TEST_ID: &str = "ipc_memory_server";
    // crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    Paths::scaffold(Some(data_dir.clone())).await?;
    let paths = Paths::new_global(data_dir.clone());

    // Setup empty accounts
    let accounts = LocalAccountSwitcher::new_with_options(Some(paths));
    let ipc_accounts = Arc::new(RwLock::new(accounts));

    let name = "mock-service";
    let version = "1.0.0";
    let build_number = 1u32;

    let app_info = ServiceAppInfo {
        name: name.to_string(),
        version: version.to_string(),
        build_number,
    };

    let mut client =
        LocalMemoryServer::listen(ipc_accounts, app_info.clone()).await?;

    let result = client.info().await?;
    assert_eq!(app_info, result);

    let mut futures = Vec::new();
    for _ in 0..100 {
        let mut client = client.clone();
        futures.push(Box::pin(async move { client.info().await }));
    }

    let results = futures::future::try_join_all(futures).await?;
    for res in results {
        assert_eq!(app_info, res);
    }

    teardown(TEST_ID).await;

    Ok(())
}
