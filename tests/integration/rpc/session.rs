use crate::test_utils::{setup, spawn, teardown};
use anyhow::Result;
use http::StatusCode;
use sos_net::{
    client::{Error, HostedOrigin, RpcClient},
    mpc::generate_keypair,
    sdk::{
        device::DeviceSigner,
        encode,
        identity::IdentityVault,
        passwd::diceware::generate_passphrase,
        signer::ecdsa::{BoxedEcdsaSigner, SingleParty},
        storage::Storage,
        sync::Client,
        vault::VaultBuilder,
        Paths,
    },
};
use std::path::PathBuf;

const TEST_ID: &str = "rpc_session";

async fn create_rpc_client(
    data_dir: PathBuf,
    origin: &HostedOrigin,
) -> Result<(RpcClient, BoxedEcdsaSigner, IdentityVault, Storage)> {
    Paths::scaffold(Some(data_dir.clone())).await?;

    let (primary_password, _) = generate_passphrase()?;
    let signer: BoxedEcdsaSigner = Box::new(SingleParty::new_random());
    let identity_vault = IdentityVault::new(
        TEST_ID.to_string(),
        primary_password,
        Some(data_dir.clone()),
    )
    .await?;
    let identity_log = identity_vault.event_log()?;

    // Set up local storage in case we need to use it
    let storage =
        Storage::new_client(signer.address()?, Some(data_dir), identity_log)
            .await?;

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

    Ok((client, signer, identity_vault, storage))
}

#[tokio::test]
async fn integration_rpc_session() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let server = spawn(TEST_ID, None, None).await?;

    let (folder_password, _) = generate_passphrase()?;

    let default_folder =
        VaultBuilder::new().password(folder_password, None).await?;
    let default_folder_buffer = encode(&default_folder).await?;

    let (client, _, _, mut storage) =
        create_rpc_client(data_dir, &server.origin).await?;

    storage.import_folder(&default_folder_buffer, None).await?;

    let account = storage.change_set().await?;

    // Create an account on the remote
    client.create_account(&account).await?;

    // Try to create the same account again
    // should yield a conflict
    let result = client.create_account(&account).await;
    assert!(matches!(
        result,
        Err(Error::ResponseCode(StatusCode::CONFLICT))
    ));

    // List folders for the account
    let summaries = client.list_folders().await?;
    // New account with a single folder
    assert_eq!(1, summaries.len());

    let sync_status = client.sync_status().await?;
    assert!(sync_status.is_some());

    let (primary_password, _) = generate_passphrase()?;

    let mut vault =
        VaultBuilder::new().password(primary_password, None).await?;
    vault.set_name(String::from("Mock vault"));
    let body = encode(&vault).await?;

    assert!(client.create_folder(&body).await.is_ok());

    // Verify new summaries length
    let summaries = client.list_folders().await?;
    assert_eq!(2, summaries.len());

    // Update and save a folder
    let name = "New vault name";
    vault.set_name(String::from(name));
    let body = encode(&vault).await?;
    assert!(client.update_folder(vault.id(), body).await.is_ok());

    // Check the list of folders includes one with the updated name
    let summaries = client.list_folders().await?;
    let new_vault_summary = summaries.iter().find(|s| s.name() == name);
    assert!(new_vault_summary.is_some());

    // Delete a folder
    assert!(client.delete_folder(vault.id()).await.is_ok());

    // Verify summaries length after deletion
    let summaries = client.list_folders().await?;
    assert_eq!(1, summaries.len());

    // Check it was the right folder that was deleted
    let del_vault_summary = summaries.iter().find(|s| s.id() == vault.id());
    assert!(del_vault_summary.is_none());

    // Load the entire event log buffer
    let login = summaries.get(0).unwrap();
    let (_proof, buffer) = client.folder_events(login.id()).await?;
    assert!(buffer.len() > 4);

    // Get the status of a remote folder
    let (_, match_proof) = client.folder_status(login.id(), None).await?;
    assert!(match_proof.is_none());

    teardown(TEST_ID).await;

    Ok(())
}
