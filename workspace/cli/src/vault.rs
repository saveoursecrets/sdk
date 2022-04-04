use anyhow::{bail, Result};
use sos_core::{
    gatekeeper::Gatekeeper,
    secret::{MetaData, Secret, SecretMeta},
    vault::Vault,
};
use std::path::PathBuf;

use crate::{
    input::{read_multiline, read_password, read_stdin},
    LOG_TARGET,
};
use log::info;

fn load_vault(vault: &PathBuf) -> Result<Gatekeeper> {
    if !vault.is_file() {
        bail!("vault file {} does not exist", vault.display());
    }
    let vault = Vault::read_file(vault)?;
    Ok(Gatekeeper::new(vault))
}

fn unlock_vault(keeper: &mut Gatekeeper, stdin: bool) -> Result<MetaData> {
    let passphrase = if stdin {
        if let Some(passphrase) = read_stdin()? {
            passphrase
        } else {
            read_password("Passphrase: ")?
        }
    } else {
        read_password("Passphrase: ")?
    };
    Ok(keeper.unlock(passphrase)?)
}

/// List the secrets in a vault.
pub fn list(vault: PathBuf) -> Result<()> {
    let mut keeper = load_vault(&vault)?;
    let meta_data = unlock_vault(&mut keeper, true)?;
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

/// Add a secret note to the vault.
pub fn add_note(vault: PathBuf, label: String) -> Result<()> {
    let mut keeper = load_vault(&vault)?;
    let _ = unlock_vault(&mut keeper, false)?;
    let delimiter = "-".repeat(60);

    info!(target: LOG_TARGET, "{}", delimiter);
    info!(target: LOG_TARGET, "To cancel and exit enter Ctrl+C");
    info!(
        target: LOG_TARGET,
        "To save the note enter Ctrl+D on a newline"
    );
    info!(target: LOG_TARGET, "{}", delimiter);
    if let Some(note) = read_multiline(None)? {
        let note = note.trim_end_matches('\n').to_string();
        let secret_meta = SecretMeta::new(label);
        let secret = Secret::Text(note);
        let uuid = keeper.set_secret(&secret, None)?;
        keeper.set_secret_meta(uuid, secret_meta)?;
        keeper.vault().write_file(vault)?;
        info!(target: LOG_TARGET, "secret {}", uuid);
    }
    Ok(())
}
