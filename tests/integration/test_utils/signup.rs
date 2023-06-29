use super::{server, TestDirs};
use anyhow::{bail, Result};
use std::path::PathBuf;
use url::Url;

use sos_sdk::{
    mpc::{generate_keypair, Keypair},
    signer::{
        ecdsa::{BoxedEcdsaSigner, SingleParty},
        Signer,
    },
    storage::UserPaths,
    vfs,
};

use web3_address::ethereum::Address;

use sos_net::client::{
    net::RpcClient,
    provider::{RemoteProvider, StorageProvider},
};

use super::{server_public_key, AccountCredentials};

pub async fn signup(
    dirs: &TestDirs,
    client_index: usize,
) -> Result<(
    Address,
    AccountCredentials,
    RemoteProvider,
    BoxedEcdsaSigner,
    Keypair,
)> {
    let TestDirs {
        target: destination,
        clients,
        ..
    } = dirs;

    let data_dir = clients.get(client_index).unwrap().to_path_buf();

    let server = server();
    let name = None;
    let signer = Box::new(SingleParty::new_random());
    let keypair = generate_keypair()?;
    let address = signer.address()?;

    let (credentials, mut node_cache) = create_account(
        server,
        destination.to_path_buf(),
        name,
        signer.clone(),
        keypair.clone(),
        data_dir,
    )
    .await?;

    println!("loading vaults in the signup...");

    let _ = node_cache.load_vaults().await?;

    Ok((address, credentials, node_cache, signer, keypair))
}

/// Login to a remote provider account.
pub async fn login(
    server: Url,
    data_dir: PathBuf,
    signer: &BoxedEcdsaSigner,
    keypair: Keypair,
) -> Result<RemoteProvider> {
    let address = signer.address()?;
    let dirs = UserPaths::new(data_dir, &address.to_string());
    let client = RpcClient::new(
        server,
        server_public_key()?,
        signer.clone(),
        keypair,
    )?;

    let mut cache = RemoteProvider::new(client, dirs).await?;

    // Prepare the client encrypted session channel
    cache.handshake().await?;

    Ok(cache)
}

/// Create a new account and remote provider.
async fn create_account(
    server: Url,
    destination: PathBuf,
    name: Option<String>,
    signer: BoxedEcdsaSigner,
    keypair: Keypair,
    data_dir: PathBuf,
) -> Result<(AccountCredentials, RemoteProvider)> {
    if !vfs::metadata(&destination).await?.is_dir() {
        bail!("not a directory {}", destination.display());
    }

    let address = signer.address()?;
    let dirs = UserPaths::new(data_dir, &address.to_string());
    let client = RpcClient::new(
        server,
        server_public_key()?,
        signer.clone(),
        keypair,
    )?;

    let mut cache = RemoteProvider::new(client, dirs).await?;

    // Prepare the client encrypted session channel
    cache.handshake().await?;

    let (_, encryption_passphrase, summary) =
        cache.create_account(name, None).await?;

    let address = signer.address()?;
    let account = AccountCredentials {
        encryption_passphrase,
        address,
        summary,
    };

    Ok((account, cache))
}
