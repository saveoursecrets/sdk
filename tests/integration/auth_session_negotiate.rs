use anyhow::Result;
use serial_test::serial;

use crate::test_utils::*;

use http::StatusCode;
use sos_core::{encode, vault::Vault};
use sos_node::{client::net::RpcClient, session::EncryptedChannel};

#[tokio::test]
#[serial]
async fn integration_auth_session_negotiate() -> Result<()> {
    let dirs = setup(1)?;

    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let server_url = server();

    let (_address, _credentials, _, signer) = signup(&dirs, 0).await?;

    let mut client = RpcClient::new(server_url, signer);

    client.authenticate().await?;

    // Should have a valid session now
    assert!(client.session().is_some());
    assert!(client.session().unwrap().ready());

    let vault: Vault = Default::default();
    let body = encode(&vault)?;

    // Try to create a new account
    let status = client.create_account(body).await?;
    assert_eq!(StatusCode::CONFLICT, status);

    // List vaults for the account
    let summaries = client.list_vaults().await?;
    // New account with a single vault
    assert_eq!(1, summaries.len());

    Ok(())
}
