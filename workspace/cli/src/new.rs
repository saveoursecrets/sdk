use anyhow::{bail, Context, Result};
use std::path::PathBuf;

use log::info;
use sos_core::{
    address::address_compressed,
    diceware,
    passphrase::{words, WordCount},
    vault::{Vault, DEFAULT_VAULT_NAME},
    Algorithm,
};
use uuid::Uuid;

use sos_readline::read_stdin;

const KEY_EXT: &str = "key.json";
const PUB_EXT: &str = "pub.json";

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

/// Print a random passphrase
pub fn passphrase(word_count: WordCount) -> Result<()> {
    println!("{}", words(word_count)?);
    Ok(())
}
