use anyhow::Result;
use sos_ipc::{
    local_account_delegate, remove_socket_file, AppIntegration, Error,
    LocalAccountIpcService, LocalAccountSocketServer, SocketClient,
};
use sos_net::sdk::{prelude::LocalAccountSwitcher, Paths};
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;

use crate::test_utils::setup;

#[tokio::test]
async fn integration_ipc_ping_pong() -> Result<()> {
    const TEST_ID: &str = "ipc_ping_pong";
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
    let (delegate, _commands) = local_account_delegate(16);

    // Start the IPC service
    let service = Arc::new(RwLock::new(LocalAccountIpcService::new(
        ipc_accounts,
        delegate,
    )));

    let server_socket_name = socket_name.clone();
    tokio::task::spawn(async move {
        LocalAccountSocketServer::listen(&server_socket_name, service)
            .await?;
        Ok::<(), Error>(())
    });

    tokio::time::sleep(Duration::from_millis(250)).await;

    let mut client = SocketClient::connect(&socket_name).await?;
    let time = client.ping().await;
    assert!(time.is_ok());

    Ok(())
}
