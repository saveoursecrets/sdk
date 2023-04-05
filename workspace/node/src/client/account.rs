//! Functions and types for creating accounts.
use sos_core::{
    generate_passphrase,
    signer::{BoxedSigner, Signer, SingleParty},
    vault::Summary,
    wal::file::WalFile,
    PatchFile,
};
use std::{convert::Infallible, path::PathBuf};
use url::Url;
use web3_address::ethereum::Address;

use super::{Error, Result};
use secrecy::{ExposeSecret, SecretString};

use crate::client::{
    net::RpcClient,
    provider::{RemoteProvider, StorageDirs, StorageProvider},
};

/// Signing key and computed address for a new account.
pub struct AccountKey(pub BoxedSigner, pub Address);

impl AccountKey {
    /// Create a signing key pair and compute the address.
    pub fn new_random() -> Result<AccountKey> {
        let signer = SingleParty::new_random();
        let address = signer.address()?;
        Ok(Self(Box::new(signer), address))
    }

    /// Get the address of the client key.
    pub fn address(&self) -> &Address {
        &self.1
    }
}

/// Encapsulates the credentials for a new account signup.
pub struct AccountCredentials {
    /// Passphrase for the vault encryption.
    pub encryption_passphrase: SecretString,
    /// Address of the signing key.
    pub address: Address,
    /// Summary that represents the login vault
    /// created when the account was created.
    pub summary: Summary,
}

/// Login to a remote provider account.
#[deprecated(note = "Use AccountManager::login()")]
pub async fn login(
    server: Url,
    cache_dir: PathBuf,
    signer: &BoxedSigner,
) -> Result<RemoteProvider<WalFile, PatchFile>> {
    let address = signer.address()?;
    let dirs = StorageDirs::new(cache_dir, &address.to_string());
    let client = RpcClient::new(server, signer.clone());

    let mut cache = RemoteProvider::new_file_cache(client, dirs)?;

    // Prepare the client encrypted session channel
    cache.authenticate().await?;

    Ok(cache)
}

/// Create a new account.
#[deprecated(note = "Use AccountManager::new_account()")]
pub async fn create_account(
    server: Url,
    destination: PathBuf,
    name: Option<String>,
    key: AccountKey,
    cache_dir: PathBuf,
    label: Option<String>,
) -> Result<(AccountCredentials, RemoteProvider<WalFile, PatchFile>)> {
    if !destination.is_dir() {
        return Err(Error::NotDirectory(destination));
    }

    let AccountKey(signer, _) = &key;
    let signing_key_bytes = signer.to_bytes();

    let address = signer.address()?;
    let dirs = StorageDirs::new(cache_dir, &address.to_string());
    let client = RpcClient::new(server, signer.clone());

    let mut cache = RemoteProvider::new_file_cache(client, dirs)?;

    // Prepare the client encrypted session channel
    cache.authenticate().await?;

    let (encryption_passphrase, summary) =
        cache.create_account(name, None).await?;

    let AccountKey(_, address) = key;
    let account = AccountCredentials {
        encryption_passphrase,
        address,
        summary,
    };

    Ok((account, cache))
}
