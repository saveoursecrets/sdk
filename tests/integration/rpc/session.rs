use anyhow::Result;
use serial_test::serial;

use crate::test_utils::*;

use http::StatusCode;
use sos_net::{
    client::{net::RpcClient, Origin},
    sdk::{encode, hex, mpc::generate_keypair, vault::Vault},
};

#[tokio::test]
#[serial]
async fn integration_auth_session_negotiate() -> Result<()> {
    let mut dirs = setup(1).await?;
    let test_data_dir = dirs.clients.remove(0);

    let (rx, _handle) = spawn()?;
    let _ = rx.await?;

    let url = server();

    let (_address, _credentials, _, signer) = signup(test_data_dir).await?;

    let public_key = server_public_key();
    let name = hex::encode(&public_key);
    let origin = Origin {
        url,
        public_key,
        name,
    };

    let mut client = RpcClient::new(origin, signer, generate_keypair()?)?;

    client.handshake().await?;

    // Noise protocol transport should be ready
    assert!(client.is_transport_ready().await);

    let vault: Vault = Default::default();
    let body = encode(&vault).await?;

    // Try to create a new account
    let (status, _) = client.create_account(body).await?.unwrap();
    assert_eq!(StatusCode::CONFLICT, status);

    // List vaults for the account
    let (_, summaries) = client.list_vaults().await?.unwrap();
    // New account with a single vault
    assert_eq!(1, summaries.len());

    let mut vault: Vault = Default::default();
    vault.set_name(String::from("Mock vault"));
    let body = encode(&vault).await?;

    let (status, proof) = client.create_vault(&body).await?.unwrap();
    assert_eq!(StatusCode::OK, status);
    assert!(proof.is_some());

    // Verify new summaries length
    let (_, summaries) = client.list_vaults().await?.unwrap();
    assert_eq!(2, summaries.len());

    // Update and save a vault
    let name = "New vault name";
    vault.set_name(String::from(name));
    let body = encode(&vault).await?;
    let (status, proof) =
        client.update_vault(vault.id(), body).await?.unwrap();
    assert_eq!(StatusCode::OK, status);
    assert!(proof.is_some());

    // Check the list of summaries includes one with the updated name
    let (_, summaries) = client.list_vaults().await?.unwrap();
    let new_vault_summary = summaries.iter().find(|s| s.name() == name);
    assert!(new_vault_summary.is_some());

    // Delete a vault
    let (status, proof) = client.delete_vault(vault.id()).await?.unwrap();
    assert_eq!(StatusCode::OK, status);
    assert!(proof.is_some());

    // Verify summaries length after deletion
    let (_, summaries) = client.list_vaults().await?.unwrap();
    assert_eq!(1, summaries.len());

    // Check it was the right vault that was deleted
    let del_vault_summary = summaries.iter().find(|s| s.id() == vault.id());
    assert!(del_vault_summary.is_none());

    // Load the entire event log buffer
    let login = summaries.get(0).unwrap();
    let (status, (proof, buffer)) =
        client.load_event_log(login.id(), None).await?.unwrap();
    assert_eq!(StatusCode::OK, status);
    assert!(proof.is_some());
    assert!(buffer.is_some());
    assert!(buffer.unwrap().len() > 4);

    // Get the status of a remote vault
    let (status, (_server_proof, match_proof)) =
        client.status(login.id(), None).await?.unwrap();
    assert_eq!(StatusCode::OK, status);
    assert!(match_proof.is_none());

    Ok(())
}
