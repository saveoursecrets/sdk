use super::{server, TestDirs};
use anyhow::{bail, Result};
use std::path::PathBuf;
use url::Url;

use sos_sdk::{
    patch::PatchFile,
    signer::{
        ecdsa::{BoxedEcdsaSigner, SingleParty},
        Signer,
    },
    storage::StorageDirs,
    wal::file::WalFile,
};

use web3_address::ethereum::Address;

use secrecy::ExposeSecret;
use sos_net::client::{
    net::RpcClient,
    provider::{RemoteProvider, StorageProvider},
};

use super::AccountCredentials;

pub async fn signup(
    dirs: &TestDirs,
    client_index: usize,
) -> Result<(
    Address,
    AccountCredentials,
    RemoteProvider,
    BoxedEcdsaSigner,
)> {
    let TestDirs {
        target: destination,
        clients,
        ..
    } = dirs;

    let cache_dir = clients.get(client_index).unwrap().to_path_buf();

    let server = server();
    let name = None;
    let signer = Box::new(SingleParty::new_random());
    let address = signer.address()?;

    let (credentials, mut node_cache) = create_account(
        server,
        destination.to_path_buf(),
        name,
        signer.clone(),
        cache_dir,
    )
    .await?;

    assert!(!credentials.encryption_passphrase.expose_secret().is_empty());

    let _ = node_cache.load_vaults().await?;

    Ok((address, credentials, node_cache, signer))
}

/// Login to a remote provider account.
pub async fn login(
    server: Url,
    cache_dir: PathBuf,
    signer: &BoxedEcdsaSigner,
) -> Result<RemoteProvider> {
    let address = signer.address()?;
    let dirs = StorageDirs::new(cache_dir, &address.to_string());
    dirs.ensure().await?;
    let client = RpcClient::new(server, signer.clone());

    let mut cache = RemoteProvider::new_file_cache(client, dirs)?;

    // Prepare the client encrypted session channel
    cache.authenticate().await?;

    Ok(cache)
}

/// Create a new account and remote provider.
async fn create_account(
    server: Url,
    destination: PathBuf,
    name: Option<String>,
    signer: BoxedEcdsaSigner,
    cache_dir: PathBuf,
) -> Result<(AccountCredentials, RemoteProvider)> {
    if !destination.is_dir() {
        bail!("not a directory {}", destination.display());
    }

    let address = signer.address()?;
    let dirs = StorageDirs::new(cache_dir, &address.to_string());
    dirs.ensure().await?;
    let client = RpcClient::new(server, signer.clone());

    let mut cache = RemoteProvider::new_file_cache(client, dirs)?;

    // Prepare the client encrypted session channel
    cache.authenticate().await?;

    let (encryption_passphrase, summary) =
        cache.create_account(name, None).await?;

    let address = signer.address()?;
    let account = AccountCredentials {
        encryption_passphrase,
        address,
        summary,
    };

    Ok((account, cache))
}
