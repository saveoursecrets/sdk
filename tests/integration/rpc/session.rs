use crate::test_utils::{setup, spawn, teardown};
use anyhow::Result;
use http::StatusCode;
use sos_net::{
    client::{HostedOrigin, RpcClient},
    mpc::generate_keypair,
    sdk::{
        account::PublicNewAccount,
        device::DeviceSigner,
        encode,
        passwd::diceware::generate_passphrase,
        signer::ecdsa::{BoxedEcdsaSigner, SingleParty},
        storage::Storage,
        vault::VaultBuilder,
    },
};
use std::path::PathBuf;

const TEST_ID: &str = "rpc_session";

async fn create_rpc_client(
    data_dir: PathBuf,
    origin: &HostedOrigin,
) -> Result<(RpcClient, BoxedEcdsaSigner)> {
    let signer: BoxedEcdsaSigner = Box::new(SingleParty::new_random());

    // Set up local storage in case we need to use it
    Storage::new_client(signer.address()?, Some(data_dir)).await?;

    let device = DeviceSigner::new_random();
    let client = RpcClient::new(
        origin.clone(),
        signer.clone(),
        device.into(),
        generate_keypair()?,
    )?;

    client.handshake().await?;

    // Noise protocol transport should be ready
    assert!(client.is_transport_ready().await);

    Ok((client, signer))
}

#[tokio::test]
async fn integration_rpc_session() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let server = spawn(TEST_ID, None, None).await?;

    let (client, signer) =
        create_rpc_client(data_dir, &server.origin).await?;

    let (primary_password, _) = generate_passphrase()?;
    let (folder_password, _) = generate_passphrase()?;

    let identity_vault = VaultBuilder::new()
        .password(primary_password, None).await?;
    let default_folder = VaultBuilder::new()
        .password(folder_password, None).await?;

    let account = PublicNewAccount {
        address: signer.address()?.clone(),
        identity_vault,
        folders: vec![default_folder],
    };

    // Create an account on the remote
    let (status, _) = client.create_account(&account).await?.unwrap();
    assert_eq!(StatusCode::OK, status);

    // Try to create the same account again
    let (status, _) = client.create_account(&account).await?.unwrap();
    assert_eq!(StatusCode::CONFLICT, status);

    // List folders for the account
    let (_, summaries) = client.list_folders().await?.unwrap();

    // New account with a single folder
    assert_eq!(1, summaries.len());

    let (_, account_status) = client.account_status().await?.unwrap();
    assert!(account_status.is_some());

    let (primary_password, _) = generate_passphrase()?;

    let mut vault =
        VaultBuilder::new().password(primary_password, None).await?;
    vault.set_name(String::from("Mock vault"));
    let body = encode(&vault).await?;

    let (status, proof) = client.create_folder(&body).await?.unwrap();
    assert_eq!(StatusCode::OK, status);
    assert!(proof.is_some());

    // Verify new summaries length
    let (_, summaries) = client.list_folders().await?.unwrap();
    assert_eq!(2, summaries.len());

    // Update and save a folder
    let name = "New vault name";
    vault.set_name(String::from(name));
    let body = encode(&vault).await?;
    let (status, proof) =
        client.update_folder(vault.id(), body).await?.unwrap();
    assert_eq!(StatusCode::OK, status);
    assert!(proof.is_some());

    // Check the list of folders includes one with the updated name
    let (_, summaries) = client.list_folders().await?.unwrap();
    let new_vault_summary = summaries.iter().find(|s| s.name() == name);
    assert!(new_vault_summary.is_some());

    // Delete a folder
    let (status, proof) = client.delete_folder(vault.id()).await?.unwrap();
    assert_eq!(StatusCode::OK, status);
    assert!(proof.is_some());

    // Verify summaries length after deletion
    let (_, summaries) = client.list_folders().await?.unwrap();
    assert_eq!(1, summaries.len());

    // Check it was the right folder that was deleted
    let del_vault_summary = summaries.iter().find(|s| s.id() == vault.id());
    assert!(del_vault_summary.is_none());

    // Load the entire event log buffer
    let login = summaries.get(0).unwrap();
    let (status, (_proof, buffer)) =
        client.load_events(login.id()).await?.unwrap();
    assert_eq!(StatusCode::OK, status);
    assert!(buffer.is_some());
    assert!(buffer.unwrap().len() > 4);

    // Get the status of a remote folder
    let (status, (_last_commit, _server_proof, match_proof)) =
        client.folder_status(login.id(), None).await?.unwrap();
    assert_eq!(StatusCode::OK, status);
    assert!(match_proof.is_none());

    teardown(TEST_ID).await;

    Ok(())
}
