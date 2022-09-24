//! Functions and types for creating accounts.
use sos_core::{
    crypto::generate_random_ecdsa_signing_key, generate_passphrase,
    signer::SingleParty, vault::Summary, wal::file::WalFile, PatchFile,
};
use std::{convert::Infallible, path::PathBuf};
use url::Url;
use web3_address::ethereum::Address;
use web3_keystore::encrypt;

use super::{node_cache::NodeCache, SignerBuilder};
use super::{Error, Result};
use secrecy::{ExposeSecret, SecretString};

/// Signing, public key and computed address for a new account.
pub struct AccountKey(pub [u8; 32], pub [u8; 33], pub Address);

impl AccountKey {
    /// Get the address of the client key.
    pub fn address(&self) -> &Address {
        &self.2
    }
}

/// Encapsulates the credentials for a new account signup.
pub struct AccountCredentials {
    /// Passphrase for the keystore.
    pub keystore_passphrase: SecretString,
    /// Passphrase for the vault encryption.
    pub encryption_passphrase: SecretString,
    /// File for the keystore.
    pub keystore_file: PathBuf,
    /// Address of the signing key.
    pub address: Address,
    /// Summary that represents the login vault
    /// created when the account was created.
    pub summary: Summary,
}

/// Login to an account.
pub async fn login(
    server: Url,
    cache_dir: PathBuf,
    keystore_file: PathBuf,
    keystore_passphrase: SecretString,
) -> Result<NodeCache<WalFile, PatchFile>> {
    if !keystore_file.exists() {
        return Err(Error::NotFile(keystore_file));
    }
    let signer = SignerBuilder::<Infallible>::new(keystore_file)
        .with_keystore_passphrase(keystore_passphrase)
        .build()?;
    let mut cache = NodeCache::new_file_cache(server, cache_dir, signer)?;

    // Prepare the client encrypted session channel
    cache.authenticate().await?;

    Ok(cache)
}

/// Create a new account.
pub async fn create_account(
    server: Url,
    destination: PathBuf,
    name: Option<String>,
    key: AccountKey,
    cache_dir: PathBuf,
    label: Option<String>,
) -> Result<(AccountCredentials, NodeCache<WalFile, PatchFile>)> {
    if !destination.is_dir() {
        return Err(Error::NotDirectory(destination));
    }

    let keystore_file = destination.join(&format!("{}.json", key.address()));
    if keystore_file.exists() {
        return Err(Error::FileExists(keystore_file));
    }

    let AccountKey(signing_key, _, _) = &key;
    let (keystore_passphrase, _) = generate_passphrase()?;
    let signer: SingleParty = (signing_key).try_into()?;
    let mut cache =
        NodeCache::new_file_cache(server, cache_dir, Box::new(signer))?;

    // Prepare the client encrypted session channel
    cache.authenticate().await?;

    let keystore = encrypt(
        &mut rand::thread_rng(),
        signing_key,
        keystore_passphrase.expose_secret(),
        Some(key.address().to_string()),
        label,
    )?;

    let (encryption_passphrase, summary) = cache.create_account(name).await?;

    std::fs::write(&keystore_file, serde_json::to_string(&keystore)?)?;

    let AccountKey(_, _, address) = key;
    let account = AccountCredentials {
        keystore_passphrase,
        encryption_passphrase,
        keystore_file,
        address,
        summary,
    };

    Ok((account, cache))
}

/// Create a signing key pair and compute the address.
pub fn create_signing_key() -> Result<AccountKey> {
    let (signing_key, public_key) = generate_random_ecdsa_signing_key();
    let address: Address = (&public_key).try_into()?;
    Ok(AccountKey(signing_key, public_key, address))
}
