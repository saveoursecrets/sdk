use anyhow::{bail, Result};
use sos_core::{vault::Vault, gatekeeper::Gatekeeper};
use std::path::PathBuf;

use crate::{password::{read_password, read_stdin}, LOG_TARGET};
use log::info;

/// List the secrets in a vault.
pub fn list(vault: PathBuf) -> Result<()> {
    if !vault.is_file() {
        bail!("vault file {} does not exist", vault.display());
    }

    let vault = Vault::read_file(vault)?;
    let mut keeper = Gatekeeper::new(vault);

    let passphrase = if let Some(passphrase) = read_stdin()? {
        passphrase
    } else {
        read_password("Passphrase: ")?
    };

    let meta_data = keeper.unlock(passphrase)?;
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
