use anyhow::{bail, Result};
use std::path::PathBuf;

use sos_core::{
    crypto::{authorize::PublicKey, keypair::KeyPart},
    vault::Vault,
};

use log::info;

use crate::LOG_TARGET;

/// List vault public keys
pub fn list(vault: PathBuf) -> Result<()> {
    if !vault.is_file() {
        bail!("vault is not a file: {}", vault.display());
    }
    let keystore = Vault::read_file(&vault)?;
    let public_keys = keystore.public_keys();
    if public_keys.is_empty() {
        info!(target: LOG_TARGET, "No public keys in {}", vault.display());
    } else {
        for public_key in public_keys {
            info!(target: LOG_TARGET, "{}", public_key.address()?);
        }
    }
    Ok(())
}

/// Add a public key to the vault
pub fn add(vault: PathBuf, public_key: PathBuf) -> Result<()> {
    if !vault.is_file() {
        bail!("vault is not a file: {}", vault.display());
    }

    let key_part: KeyPart =
        serde_json::from_str(&std::fs::read_to_string(&public_key)?)?;
    let public_key: PublicKey = key_part.try_into()?;
    let mut keystore = Vault::read_file(&vault)?;
    let address = public_key.address()?;

    if keystore.get_public_key(&public_key).is_some() {
        bail!("public key {} already exists", address);
    } else {
        keystore.add_public_key(public_key);
        keystore.write_file(vault)?;
        info!(target: LOG_TARGET, "added public key {}", address);
    }

    Ok(())
}

/// Remove a public key from the vault
pub fn remove(vault: PathBuf, public_key: PathBuf) -> Result<()> {
    if !vault.is_file() {
        bail!("vault is not a file: {}", vault.display());
    }

    let key_part: KeyPart =
        serde_json::from_str(&std::fs::read_to_string(&public_key)?)?;
    let public_key: PublicKey = key_part.try_into()?;
    let mut keystore = Vault::read_file(&vault)?;
    let address = public_key.address()?;

    if keystore.get_public_key(&public_key).is_none() {
        bail!("public key {} does not exist", address);
    } else {
        keystore.remove_public_key(&public_key);
        keystore.write_file(vault)?;
        info!(target: LOG_TARGET, "removed public key {}", address);
    }

    Ok(())
}
