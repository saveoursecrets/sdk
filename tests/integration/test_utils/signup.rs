use super::{server, TestDirs};
use anyhow::{bail, Result};
use std::path::PathBuf;
use url::Url;

use web3_address::ethereum::Address;

use sos_net::{
    client::{
        net::RpcClient,
        provider::{RemoteProvider, StorageProvider},
    },
    sdk::{
        mpc::{generate_keypair, Keypair},
        signer::{
            ecdsa::{BoxedEcdsaSigner, SingleParty},
            Signer,
        },
        storage::UserPaths,
        vfs,
    },
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

    let (credentials, mut provider) = create_account(
        server,
        destination.to_path_buf(),
        name,
        signer.clone(),
        keypair,
        data_dir,
    )
    .await?;

    let _ = provider.local_mut().load_vaults().await?;
    Ok((address, credentials, provider, signer))
}

/// Login to a remote provider account.
pub async fn login(
    signer: &BoxedEcdsaSigner,
) -> Result<RemoteProvider> {
    use crate::sync::create_remote_provider;
    let (_origin, provider) = create_remote_provider(signer.clone()).await?;
    Ok(provider)
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

    use crate::sync::create_remote_provider;

    let address = signer.address()?;
    let (origin, mut provider) = create_remote_provider(signer).await?;
    
    let (_, encryption_passphrase, summary) =
        provider.local_mut().create_account(name, None).await?;

    let account = AccountCredentials {
        encryption_passphrase,
        address,
        summary,
    };

    Ok((account, provider))
}
