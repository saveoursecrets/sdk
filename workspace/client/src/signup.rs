//! Signup a new account.
use crate::{
    display_passphrase, run_blocking, Client, ClientCache, Error, FileCache,
    Result,
};
use sos_core::{
    address::AddressStr, crypto::generate_random_ecdsa_signing_key,
    generate_passphrase, signer::SingleParty,
};
use sos_readline::read_flag;
use std::{borrow::Cow, path::PathBuf, sync::Arc};
use terminal_banner::{Banner, Padding};
use url::Url;
use web3_keystore::encrypt;

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
}

/// Create a new account.
pub async fn create_account(
    server: Url,
    destination: PathBuf,
    name: Option<String>,
    key: ClientKey,
) -> Result<ClientCredentials> {
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
    let cache_dir = FileCache::cache_dir()?;
    let mut cache = FileCache::new(client, cache_dir, true)?;

    let keystore = encrypt(
        &mut rand::thread_rng(),
        signing_key,
        &keystore_passphrase,
        Some(key.address().to_string()),
    )?;

    let encryption_passphrase = cache.create_account(name).await?;
    std::fs::write(&keystore_file, serde_json::to_string(&keystore)?)?;

    let ClientKey(_, _, address) = key;
    let account = ClientCredentials {
        keystore_passphrase,
        encryption_passphrase,
        keystore_file,
        address,
    };

    Ok(account)
}

/// Create a signing key pair and compute the address.
pub fn create_signing_key() -> Result<ClientKey> {
    let (signing_key, public_key) = generate_random_ecdsa_signing_key();
    let address: AddressStr = (&public_key).try_into()?;
    Ok(ClientKey(signing_key, public_key, address))
}

pub fn signup(
    server: Url,
    destination: PathBuf,
    name: Option<String>,
) -> Result<()> {
    if !destination.is_dir() {
        return Err(Error::NotDirectory(destination));
    }

    let client_key = create_signing_key()?;
    let keystore_file =
        destination.join(&format!("{}.json", client_key.address()));
    if keystore_file.exists() {
        return Err(Error::FileExists(keystore_file));
    }

    let message = format!(
        r#"* Write keystore file to {}
* Send the encrypted vault to {}
* Keystore passphrase will be displayed
* Encryption passphrase will be displayed"#,
        keystore_file.display(),
        server
    );

    let banner = Banner::new()
        .padding(Padding::one())
        .text(Cow::Borrowed(
            "Creating a new account will perform the following actions:",
        ))
        .text(Cow::Owned(message))
        .render();

    println!("{}", banner);

    let prompt = Some("Are you sure (y/n)? ");
    if read_flag(prompt)? {
        let account = run_blocking(create_account(
            server,
            destination,
            name,
            client_key,
        ))?;

        display_passphrase(
            "KEYSTORE PASSPHRASE",
            &account.keystore_passphrase,
        );
        display_passphrase(
            "ENCRYPTION PASSPHRASE",
            &account.encryption_passphrase,
        );
    }
    Ok(())
}
