use anyhow::{anyhow, bail, Result};
use sos_core::{
    client::{MemoryClient, VaultClient},
    crypto::{
        authorize::{jwt::KeyPair, PrivateKey},
        keypair::KeyPart,
    },
    service::{MemoryService, VaultService},
    vault::Vault,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use log::info;

const PASSPHRASE_PROMPT: &str = "Passphrase: ";

fn passphrase_prompt(prompt: &str) -> Result<String> {
    todo!()
    //let passphrase = prompt_password(prompt)?;
    //if passphrase.trim().is_empty() {
    //return passphrase_prompt(prompt);
    //}
    //Ok(passphrase)
}

fn get_service(vault: PathBuf, jwt_keypair: PathBuf) -> Result<MemoryService> {
    if !vault.is_file() {
        bail!("vault is not a file: {}", vault.display());
    }

    let label = vault
        .file_stem()
        .ok_or_else(|| {
            anyhow!(
                "unable to extract file stem for vault file, {}",
                vault.display()
            )
        })?
        .to_string_lossy()
        .to_string();

    if !jwt_keypair.is_file() {
        bail!("keypair for JWT is not a file: {}", jwt_keypair.display());
    }

    let vault = Vault::read_file(&vault)?;
    let jwt_pem = std::fs::read_to_string(jwt_keypair)?;
    let jwt_keypair = KeyPair::from_pem(&jwt_pem)?;

    let mut vaults = HashMap::new();
    vaults.insert(label, Arc::new(RwLock::new(vault)));

    Ok(MemoryService::new(jwt_keypair, vaults))
}

fn get_private_key<'a>(auth_private_key: PathBuf) -> Result<PrivateKey> {
    if !auth_private_key.is_file() {
        bail!(
            "auth private key is not a file: {}",
            auth_private_key.display()
        );
    }

    let private_key_bytes = std::fs::read(&auth_private_key)?;
    let key_part: KeyPart = serde_json::from_slice(&private_key_bytes)?;
    let private_key: PrivateKey = key_part.into();
    Ok(private_key)
}

fn get_client<'a>(
    service: &'a mut impl VaultService,
    private_key: &PrivateKey,
) -> Result<MemoryClient<'a>> {
    Ok(MemoryClient::new(service, private_key)?)
}

/// List the contents of a vault.
pub fn list(
    vault: PathBuf,
    jwt_keypair: PathBuf,
    auth_private_key: PathBuf,
) -> Result<()> {
    let mut service = get_service(vault, jwt_keypair)?;
    let private_key = get_private_key(auth_private_key)?;
    let mut client = get_client(&mut service, &private_key)?;

    info!("Enter your passphrase to unlock the vault");
    info!("");

    let passphrase = passphrase_prompt(PASSPHRASE_PROMPT)?;
    let passphrase_bytes = passphrase.as_bytes().to_vec();
    client.set_encryption_key(Some(passphrase_bytes));

    info!("Run listing vault content {}", passphrase);

    Ok(())
}
