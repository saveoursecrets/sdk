use anyhow::{bail, Context, Result};
use std::path::PathBuf;

use sos_core::{
    crypto::{authorize::jwt, keypair::generate},
    passphrase::{words, WordCount},
    vault::Vault,
};

use log::info;

const KEY_EXT: &str = "key.json";
const PUB_EXT: &str = "pub.json";
const PEM_EXT: &str = "pem";
const SOS_EXT: &str = "sos3";

use crate::LOG_TARGET;

/// Create a new empty vault
pub fn vault(name: String, destination: PathBuf) -> Result<()> {
    if !destination.is_dir() {
        bail!("destination is not a directory: {}", destination.display());
    }

    let mut vault_path = destination.join(&name);
    vault_path.set_extension(SOS_EXT);

    if vault_path.exists() {
        bail!("file {} already exists", vault_path.display());
    }

    let vault: Vault = Default::default();
    vault.write_file(&vault_path)?;

    info!(
        target: LOG_TARGET,
        "wrote vault to {}",
        vault_path.display()
    );
    Ok(())
}

/// Create a new keypair
pub fn keypair(name: String, destination: PathBuf) -> Result<()> {
    if !destination.is_dir() {
        bail!("destination is not a directory: {}", destination.display());
    }

    let keypair = generate();
    let (private, public) = keypair.split();
    let private = serde_json::to_string_pretty(&private)?;
    let public = serde_json::to_string_pretty(&public)?;

    let mut private_path = destination.join(&name);
    let mut public_path = destination.join(&name);

    private_path.set_extension(KEY_EXT);
    public_path.set_extension(PUB_EXT);

    if private_path.exists() {
        bail!("file {} already exists", private_path.display());
    }

    if public_path.exists() {
        bail!("file {} already exists", public_path.display());
    }

    std::fs::write(&private_path, private).with_context(|| {
        format!("failed to write to {}", private_path.display())
    })?;
    info!(
        target: LOG_TARGET,
        "wrote private key to {}",
        private_path.display()
    );

    std::fs::write(&public_path, public).with_context(|| {
        format!("failed to write to {}", private_path.display())
    })?;
    info!(
        target: LOG_TARGET,
        "wrote public key to {}",
        public_path.display()
    );
    Ok(())
}

/// Create a new JWT keypair
pub fn jwt(name: String, destination: PathBuf) -> Result<()> {
    if !destination.is_dir() {
        bail!("destination is not a directory: {}", destination.display());
    }

    let keypair = jwt::generate();
    let key = keypair.to_pem();

    let mut keypair_path = destination.join(&name);
    keypair_path.set_extension(PEM_EXT);

    if keypair_path.exists() {
        bail!("file {} already exists", keypair_path.display());
    }

    std::fs::write(&keypair_path, &key).with_context(|| {
        format!("failed to write to {}", keypair_path.display())
    })?;
    info!(
        target: LOG_TARGET,
        "wrote key to {}",
        keypair_path.display()
    );

    Ok(())
}

/// Print a random passphrase
pub fn passphrase(word_count: WordCount) -> Result<()> {
    println!("{}", words(word_count)?);
    Ok(())
}
