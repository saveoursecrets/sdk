use anyhow::Result;
use sos_ipc::{
    remove_socket_file, AppIntegration, Error, ServiceAppInfo,
    ServiceOptions, SocketClient, SocketServer,
};
use sos_net::sdk::{prelude::LocalAccountSwitcher, Paths};
use sos_test_utils::teardown;
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;

use crate::test_utils::setup;

#[tokio::test]
async fn integration_ipc_app_info() -> Result<()> {
    const TEST_ID: &str = "ipc_app_info";
    // crate::test_utils::init_tracing();

    let socket_name = format!("{}.sock", TEST_ID);

    // Must clean up the tmp file on MacOS
    remove_socket_file(&socket_name);

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

    // Start the IPC service
    /*
    let service = Arc::new(RwLock::new(IpcService::new(
        ipc_accounts,
    )));
    */

    let options = ServiceOptions {
        app_info: Some(ServiceAppInfo {
            name: name.to_string(),
            version: version.to_string(),
            build_number,
        }),
        ..Default::default()
    };

    let server_socket_name = socket_name.clone();
    tokio::task::spawn(async move {
        SocketServer::listen(&server_socket_name, ipc_accounts, options)
            .await?;
        Ok::<(), Error>(())
    });

    tokio::time::sleep(Duration::from_millis(250)).await;

    let mut client = SocketClient::connect(&socket_name).await?;
    let info = client.info().await?;
    assert_eq!(name, &info.name);
    assert_eq!(version, &info.version);
    assert_eq!(build_number, info.build_number);

    teardown(TEST_ID).await;

    Ok(())
}
