use sos_ipc::{
    Error, IpcClient, NetworkAccountIpcServer, NetworkAccountIpcService,
    Result,
};
use sos_net::{
    sdk::prelude::Address, NetworkAccount, NetworkAccountSwitcher,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;

#[tokio::test]
async fn list_authenticated_accounts() -> Result<()> {
    let unauth_address = Address::random();
    let mut accounts = NetworkAccountSwitcher::new();
    accounts.add_account(
        NetworkAccount::new_unauthenticated(
            unauth_address,
            None,
            Default::default(),
        )
        .await?,
    );
    let service =
        Arc::new(Mutex::new(NetworkAccountIpcService::new(accounts)));

    tokio::task::spawn(async move {
        NetworkAccountIpcServer::listen("127.0.0.1:5353", service).await?;
        Ok::<(), Error>(())
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    let mut client = IpcClient::connect("127.0.0.1:5353").await?;

    let accounts = client.authenticated().await?;
    assert_eq!(1, accounts.len());
    assert_eq!(false, *accounts.get(&unauth_address).unwrap());

    Ok(())
}
