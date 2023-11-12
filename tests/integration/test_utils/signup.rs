use super::{server, TestDirs};
use anyhow::{bail, Result};
use std::path::PathBuf;
use url::Url;

use web3_address::ethereum::Address;

use sos_net::{
    client::{
        net::RpcClient,
        provider::{RemoteProvider, StorageProvider, new_local_provider, LocalProvider},
        RemoteSync,
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

use super::{server_public_key, AccountCredentials, create_remote_provider};

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
    let address = signer.address()?;

    let (credentials, mut provider) = create_account(
        server,
        destination.to_path_buf(),
        name,
        signer.clone(),
        data_dir,
    )
    .await?;

    provider.sync().await?;

    Ok((address, credentials, provider, signer))
}

pub async fn signup_local(default_folder_name: Option<String>) -> Result<(
    Address,
    AccountCredentials,
    LocalProvider,
    BoxedEcdsaSigner,
)> {
    let signer = Box::new(SingleParty::new_random());
    let address = signer.address()?;
    let (credentials, provider) =
        create_local_account(default_folder_name, signer.clone()).await?;
    Ok((address, credentials, provider, signer))
}

/// Login to a remote provider account.
pub async fn login(
    signer: &BoxedEcdsaSigner,
) -> Result<RemoteProvider> {
    let (_origin, provider) = create_remote_provider(signer.clone()).await?;
    Ok(provider)
}

/// Create a new account and remote provider.
async fn create_account(
    server: Url,
    destination: PathBuf,
    name: Option<String>,
    signer: BoxedEcdsaSigner,
    data_dir: PathBuf,
) -> Result<(AccountCredentials, RemoteProvider)> {
    if !vfs::metadata(&destination).await?.is_dir() {
        bail!("not a directory {}", destination.display());
    }

    let address = signer.address()?;
    let (origin, provider) = create_remote_provider(signer).await?;

    let local_provider = provider.local();
    let mut local_writer = local_provider.write().await;
    
    let (_, encryption_passphrase, summary) =
        local_writer.create_account(name, None).await?;

    let account = AccountCredentials {
        encryption_passphrase,
        address,
        summary,
    };

    Ok((account, provider))
}

/// Create a new account and local provider.
async fn create_local_account(
    default_folder_name: Option<String>,
    signer: BoxedEcdsaSigner,
) -> Result<(AccountCredentials, LocalProvider)> {
    let address = signer.address()?;
    let (mut provider, _) = new_local_provider(signer).await?;
    let (_, encryption_passphrase, summary) =
        provider.create_account(default_folder_name, None).await?;
    let account = AccountCredentials {
        encryption_passphrase,
        address,
        summary,
    };
    Ok((account, provider))
}
