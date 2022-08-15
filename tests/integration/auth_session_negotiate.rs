use anyhow::Result;
use serial_test::serial;

use crate::test_utils::*;

use http::StatusCode;
use sos_core::{encode, vault::Vault};
use sos_node::client::net::RpcClient;

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
    assert!(client.has_session());
    assert!(client.is_ready()?);

    let vault: Vault = Default::default();
    let body = encode(&vault)?;

    // Try to create a new account
    let status = client.create_account(body).await?;
    assert_eq!(StatusCode::CONFLICT, status);

    // List vaults for the account
    let summaries = client.list_vaults().await?;
    // New account with a single vault
    assert_eq!(1, summaries.len());

    let mut vault: Vault = Default::default();
    vault.set_name(String::from("Mock vault"));
    let body = encode(&vault)?;

    let (status, proof) = client.create_vault(body).await?;

    assert_eq!(StatusCode::OK, status);
    assert!(proof.is_some());

    // Update and save a vault
    let name = "New vault name";
    vault.set_name(String::from(name));
    let body = encode(&vault)?;
    let (status, proof) = client.save_vault(vault.id(), body).await?;
    assert_eq!(StatusCode::OK, status);
    assert!(proof.is_some());

    // Verify new summaries length
    let summaries = client.list_vaults().await?;
    assert_eq!(2, summaries.len());

    // Check the list of summaries includes one with the updated name
    let new_vault_summary = summaries.iter().find(|s| s.name() == name);
    assert!(new_vault_summary.is_some());

    // Delete a vault
    let (status, proof) = client.delete_vault(vault.id()).await?;
    assert_eq!(StatusCode::OK, status);
    assert!(proof.is_some());

    // Verify summaries length after deletion
    let summaries = client.list_vaults().await?;
    assert_eq!(1, summaries.len());

    // Check it was the right vault that was deleted
    let del_vault_summary = summaries.iter().find(|s| s.id() == vault.id());
    assert!(del_vault_summary.is_none());

    let login = summaries.get(0).unwrap();

    // Load the entire WAL buffer
    let (status, proof, buffer) = client.load_wal(login.id(), None).await?;
    assert_eq!(StatusCode::OK, status);
    assert!(proof.is_some());
    assert!(buffer.is_some());
    assert!(buffer.unwrap().len() > 4);

    // Get the status of a remote vault
    let (status, _server_proof, match_proof) =
        client.status(login.id(), None).await?;
    assert_eq!(StatusCode::OK, status);
    assert!(match_proof.is_none());

    Ok(())
}
