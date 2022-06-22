use std::path::PathBuf;

use sos_core::{
    address::address_compressed,
    diceware,
    passphrase::{words, WordCount},
    vault::{Vault, DEFAULT_VAULT_NAME},
    Algorithm,
};
use uuid::Uuid;

use sos_readline::read_stdin;

use crate::{Error, Result};

/// Create a new empty vault
pub fn vault(
    destination: PathBuf,
    name: Option<String>,
    uuid: Option<Uuid>,
    algorithm: Option<Algorithm>,
) -> Result<()> {
    if !destination.is_dir() {
        return Err(Error::NotDirectory(destination));
    }

    let uuid = uuid.unwrap_or_else(Uuid::new_v4);
    let file_name = uuid.to_string();

    let mut vault_path = destination.join(&file_name);
    vault_path.set_extension(Vault::extension());

    if vault_path.exists() {
        return Err(Error::FileExists(vault_path));
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

    tracing::info!("wrote vault to {}", vault_path.display());

    if generated {
        let delimiter = "-".repeat(60);
        tracing::info!("generated diceware passphrase");
        tracing::info!("{}", delimiter);
        tracing::info!("{}", passphrase);
        tracing::info!("{}", delimiter);
    }
    Ok(())
}
