use anyhow::{bail, Context, Result};
use std::path::PathBuf;

use log::info;
use sos_core::{
    address::address_compressed,
    crypto::{authorize::jwt, keypair::generate},
    diceware,
    passphrase::{words, WordCount},
    vault::{Vault, DEFAULT_VAULT_NAME},
    Algorithm,
};
use uuid::Uuid;

use sos_readline::read_stdin;

const KEY_EXT: &str = "key.json";
const PUB_EXT: &str = "pub.json";
const PEM_EXT: &str = "pem";

use crate::LOG_TARGET;

/// Create a new empty vault
pub fn vault(
    destination: PathBuf,
    name: Option<String>,
    uuid: Option<Uuid>,
    algorithm: Option<Algorithm>,
) -> Result<()> {
    if !destination.is_dir() {
        bail!("destination is not a directory: {}", destination.display());
    }

    let uuid = uuid.unwrap_or_else(Uuid::new_v4);
    let file_name = uuid.to_string();

    let mut vault_path = destination.join(&file_name);
    vault_path.set_extension(Vault::extension());

    if vault_path.exists() {
        bail!("file {} already exists", vault_path.display());
    }

    let (passphrase, generated) = if let Some(passphrase) = read_stdin()? {
        (passphrase, false)
    } else {
        let (passphrase, _) = diceware::generate()?;
        (passphrase, true)
    };

    let algorithm = if let Some(algo) = algorithm {
        algo
    } else {
        Default::default()
    };

    let name = name.unwrap_or_else(|| String::from(DEFAULT_VAULT_NAME));

    let mut vault = Vault::new(uuid, name, algorithm);
    vault.initialize(&passphrase)?;
    vault.write_file(&vault_path)?;

    info!(
        target: LOG_TARGET,
        "wrote vault to {}",
        vault_path.display()
    );

    if generated {
        let delimiter = "-".repeat(60);
        info!(target: LOG_TARGET, "generated diceware passphrase");
        info!(target: LOG_TARGET, "{}", delimiter);
        info!(target: LOG_TARGET, "{}", passphrase);
        info!(target: LOG_TARGET, "{}", delimiter);
    }
    Ok(())
}

/// Create a new keypair
pub fn keypair(name: String, destination: PathBuf) -> Result<()> {
    if !destination.is_dir() {
        bail!("destination is not a directory: {}", destination.display());
    }

    let keypair = generate();
    let (private, public) = keypair.split();

    let public_key_bytes: [u8; 33] = public.key.as_slice().try_into()?;
    let address = address_compressed(&public_key_bytes)?;

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

    info!("{}", address);
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
