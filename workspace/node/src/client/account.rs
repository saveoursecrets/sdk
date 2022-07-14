//! Signup a new account.
use crate::{Client, ClientCache, Error, FileCache, Result};
use sos_core::{
    address::AddressStr, crypto::generate_random_ecdsa_signing_key,
    generate_passphrase, signer::SingleParty, vault::Summary,
};
use std::{convert::Infallible, path::PathBuf, sync::Arc};
use url::Url;
use web3_keystore::encrypt;

use super::ClientBuilder;

/// Signing, public key and computed address for a new client account.
pub struct ClientKey(pub [u8; 32], pub [u8; 33], pub AddressStr);

impl ClientKey {
    /// Get the address of the client key.
    pub fn address(&self) -> &AddressStr {
        &self.2
    }
}

/// Encapsulates the credentials for a new account signup.
pub struct ClientCredentials {
    pub keystore_passphrase: String,
    pub encryption_passphrase: String,
    pub keystore_file: PathBuf,
    pub address: AddressStr,
    pub summary: Summary,
}

/// Login to an account.
pub fn login(
    server: Url,
    cache_dir: PathBuf,
    keystore_file: PathBuf,
    keystore_passphrase: String,
) -> Result<FileCache> {
    if !keystore_file.exists() {
        return Err(Error::NotFile(keystore_file));
    }
    let client = ClientBuilder::<Infallible>::new(server, keystore_file)
        .with_keystore_passphrase(keystore_passphrase)
        .build()?;
    Ok(FileCache::new(client, cache_dir, true)?)
}

/// Create a new account.
pub async fn create_account(
    server: Url,
    destination: PathBuf,
    name: Option<String>,
    key: ClientKey,
    cache_dir: PathBuf,
) -> Result<(ClientCredentials, FileCache)> {
    if !destination.is_dir() {
        return Err(Error::NotDirectory(destination));
    }

    let keystore_file = destination.join(&format!("{}.json", key.address()));
    if keystore_file.exists() {
        return Err(Error::FileExists(keystore_file));
    }

    let ClientKey(signing_key, _, _) = &key;
    let (keystore_passphrase, _) = generate_passphrase()?;
    let signer: SingleParty = (signing_key).try_into()?;
    let client = Client::new(server, Arc::new(signer));
    let mut cache = FileCache::new(client, cache_dir, true)?;

    let keystore = encrypt(
        &mut rand::thread_rng(),
        signing_key,
        &keystore_passphrase,
        Some(key.address().to_string()),
    )?;

    let (encryption_passphrase, summary) = cache.create_account(name).await?;
    std::fs::write(&keystore_file, serde_json::to_string(&keystore)?)?;

    let ClientKey(_, _, address) = key;
    let account = ClientCredentials {
        keystore_passphrase,
        encryption_passphrase,
        keystore_file,
        address,
        summary,
    };

    Ok((account, cache))
}

/// Create a signing key pair and compute the address.
pub fn create_signing_key() -> Result<ClientKey> {
    let (signing_key, public_key) = generate_random_ecdsa_signing_key();
    let address: AddressStr = (&public_key).try_into()?;
    Ok(ClientKey(signing_key, public_key, address))
}
