use anyhow::{bail, Result};
use sos_core::{gatekeeper::Gatekeeper, secret::MetaData, vault::Vault};
use std::path::PathBuf;

use crate::{
    password::{read_multiline, read_password, read_stdin},
    LOG_TARGET,
};
use log::info;

fn load_vault(vault: PathBuf) -> Result<Gatekeeper> {
    if !vault.is_file() {
        bail!("vault file {} does not exist", vault.display());
    }
    let vault = Vault::read_file(vault)?;
    Ok(Gatekeeper::new(vault))
}

fn unlock_vault(keeper: &mut Gatekeeper) -> Result<MetaData> {
    let passphrase = if let Some(passphrase) = read_stdin()? {
        passphrase
    } else {
        read_password("Passphrase: ")?
    };
    Ok(keeper.unlock(passphrase)?)
}

/// List the secrets in a vault.
pub fn list(vault: PathBuf) -> Result<()> {
    let mut keeper = load_vault(vault)?;
    let meta_data = unlock_vault(&mut keeper)?;
    let secrets = meta_data.secrets();
    if secrets.is_empty() {
        info!(target: LOG_TARGET, "Empty vault");
    } else {
        for (id, meta) in secrets {
            info!(target: LOG_TARGET, "{} -> {}", meta.label(), id);
        }
    }
    Ok(())
}

/// Add a note to the vault.
pub fn note(vault: PathBuf) -> Result<()> {
    let mut keeper = load_vault(vault)?;
    let meta_data = unlock_vault(&mut keeper)?;

    info!(target: LOG_TARGET, "Enter the note:");
    if let Some(note) = read_multiline(None)? {
        println!("'{}'", note);
    }

    /*
    let secrets = meta_data.secrets();
    if secrets.is_empty() {
        info!(target: LOG_TARGET, "Empty vault");
    } else {
        for (id, meta) in secrets {
            info!(target: LOG_TARGET, "{} -> {}", meta.label(), id);
        }
    }
    */
    Ok(())
}
