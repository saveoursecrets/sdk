use anyhow::{anyhow, bail, Result};
use sos_core::{
    gatekeeper::Gatekeeper,
    secret::{MetaData, Secret, SecretMeta},
    vault::Vault,
};
use std::{path::PathBuf, collections::HashMap};
use url::Url;

use crate::{
    input::{
        read_flag, read_line, read_multiline, read_option, read_password,
        read_stdin,
    },
    UuidOrName, LOG_TARGET,
};
use log::{error, info, warn};

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
            read_password(Some("Passphrase: "))?
        }
    } else {
        read_password(Some("Passphrase: "))?
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
            info!(
                target: LOG_TARGET,
                "[{}] \"{}\" {}",
                Secret::type_name(*meta.kind()),
                meta.label(),
                id
            );
        }
    }
    Ok(())
}

fn print_secret_header(secret: &Secret, secret_meta: &SecretMeta) {
    let delimiter = "-".repeat(60);
    println!("{}", delimiter);
    println!(
        "{}: {}",
        Secret::type_name(secret.kind()),
        secret_meta.label()
    );
    println!("{}", delimiter);
}

/// Show a secret from the vault.
pub fn show(vault: PathBuf, target: UuidOrName) -> Result<()> {
    let mut keeper = load_vault(&vault)?;
    let meta_data = unlock_vault(&mut keeper, true)?;

    let result = match &target {
        UuidOrName::Uuid(uuid) => {
            meta_data.secrets().get(uuid).map(|v| (uuid, v))
        }
        UuidOrName::Name(name) => {
            meta_data.secrets().iter().find_map(|(k, v)| {
                if v.label() == name {
                    return Some((k, v));
                } else {
                    None
                }
            })
        }
    };

    if let Some((uuid, secret_meta)) = result {
        match keeper.get(uuid) {
            Ok(Some((_, secret))) => match secret {
                Secret::Text(ref note) => {
                    print_secret_header(&secret, secret_meta);
                    println!("{}", note);
                }
                _ => todo!("print other secret types"),
            },
            Ok(None) => info!(target: LOG_TARGET, "secret not found"),
            Err(e) => return Err(anyhow!(e)),
        }
    } else {
        // Secret meta data not found
        log::info!(target: LOG_TARGET, "secret not found");
    }
    Ok(())
}

/// Remove a secret from the vault.
pub fn remove(vault: PathBuf, target: UuidOrName) -> Result<()> {
    let mut keeper = load_vault(&vault)?;
    let meta_data = unlock_vault(&mut keeper, true)?;

    let result = match &target {
        UuidOrName::Uuid(uuid) => {
            meta_data.secrets().get(uuid).map(|v| (uuid, v))
        }
        UuidOrName::Name(name) => {
            meta_data.secrets().iter().find_map(|(k, v)| {
                if v.label() == name {
                    return Some((k, v));
                } else {
                    None
                }
            })
        }
    };

    if let Some((uuid, _)) = result {
        let delimiter = "-".repeat(60);
        warn!(target: LOG_TARGET, "{}", delimiter);
        warn!(target: LOG_TARGET, "DELETING A SECRET IS IRREVERSIBLE!");
        warn!(target: LOG_TARGET, "{}", delimiter);

        let prompt =
            Some("Are you sure you want to delete this secret (y/n)? ");
        if read_flag(prompt)? {
            keeper.remove(uuid)?;
            keeper.vault().write_file(vault)?;
            log::info!(target: LOG_TARGET, "removed secret {}", uuid);
        }
    } else {
        // Secret meta data not found
        log::info!(target: LOG_TARGET, "secret not found");
    }
    Ok(())
}

/// Add a secret account to the vault.
pub fn add_account(vault: PathBuf, label: Option<String>) -> Result<()> {
    let mut keeper = load_vault(&vault)?;
    let meta = unlock_vault(&mut keeper, false)?;

    let mut label = if let Some(label) = label {
        label
    } else {
        read_line(Some("Label: "))?
    };

    while meta.find_by_label(&label).is_some() {
        error!(target: LOG_TARGET, "secret already exists for '{}'", &label);
        label = read_line(Some("Label: "))?
    }

    let account = read_line(Some("Account name: "))?;
    let url = read_option(Some("Website URL: "))?;
    let password = read_password(Some("Password: "))?;

    let url: Option<Url> = if let Some(url) = url {
        Some(url.parse()?)
    } else {
        None
    };

    let secret = Secret::Account {
        account,
        url,
        password,
    };
    let secret_meta = SecretMeta::new(label, secret.kind());
    let uuid = keeper.add(secret_meta, secret)?;
    keeper.vault().write_file(vault)?;
    info!(target: LOG_TARGET, "saved secret {}", uuid);
    Ok(())
}

/// Add a secret note to the vault.
pub fn add_note(vault: PathBuf, label: Option<String>) -> Result<()> {
    let mut keeper = load_vault(&vault)?;
    let meta = unlock_vault(&mut keeper, false)?;
    let delimiter = "-".repeat(60);

    let mut label = if let Some(label) = label {
        label
    } else {
        read_line(Some("Label: "))?
    };

    while meta.find_by_label(&label).is_some() {
        error!(target: LOG_TARGET, "secret already exists for '{}'", &label);
        label = read_line(Some("Label: "))?
    }

    info!(target: LOG_TARGET, "{}", delimiter);
    info!(target: LOG_TARGET, "To cancel and exit enter Ctrl+C");
    info!(
        target: LOG_TARGET,
        "To save the note enter Ctrl+D on a newline"
    );
    info!(target: LOG_TARGET, "{}", delimiter);
    if let Some(note) = read_multiline(None)? {
        let note = note.trim_end_matches('\n').to_string();
        let secret = Secret::Text(note);
        let secret_meta = SecretMeta::new(label, secret.kind());
        let uuid = keeper.add(secret_meta, secret)?;
        keeper.vault().write_file(vault)?;
        info!(target: LOG_TARGET, "saved secret {}", uuid);
    }
    Ok(())
}

/// Add a secret file to the vault.
pub fn add_file(
    vault: PathBuf,
    label: Option<String>,
    file: PathBuf,
) -> Result<()> {
    if !file.is_file() {
        bail!("file {} does not exist", file.display());
    }

    let mut keeper = load_vault(&vault)?;
    let meta = unlock_vault(&mut keeper, false)?;

    let mime = if let Some(name) = file.file_name() {
        if let Some(name) = name.to_str() {
            mime_guess::from_path(name).first().map(|m| m.to_string())
        } else {
            None
        }
    } else {
        None
    };

    let mut label = if let Some(label) = label {
        label
    } else {
        file.file_name()
            .ok_or(anyhow!("not a valid filename"))
            .map(|name| name.to_string_lossy().into_owned())?
    };

    while meta.find_by_label(&label).is_some() {
        error!(target: LOG_TARGET, "secret already exists for '{}'", &label);
        label = read_line(Some("Label: "))?
    }

    let buffer = std::fs::read(file)?;
    let secret = Secret::Blob { buffer, mime };
    let secret_meta = SecretMeta::new(label, secret.kind());
    let uuid = keeper.add(secret_meta, secret)?;
    keeper.vault().write_file(vault)?;
    info!(target: LOG_TARGET, "saved secret {}", uuid);
    Ok(())
}

/// Add a credentials list to the vault.
pub fn add_credentials(vault: PathBuf, label: Option<String>) -> Result<()> {
    let mut keeper = load_vault(&vault)?;
    let meta = unlock_vault(&mut keeper, false)?;

    let mut label = if let Some(label) = label {
        label
    } else {
        read_line(Some("Label: "))?
    };

    while meta.find_by_label(&label).is_some() {
        error!(target: LOG_TARGET, "secret already exists for '{}'", &label);
        label = read_line(Some("Label: "))?;
    }

    let mut credentials: HashMap<String, String> = HashMap::new();
    loop {
        let mut name = read_line(Some("Name: "))?;
        while credentials.get(&name).is_some() {
            error!(target: LOG_TARGET, "name '{}' already exists", &name);
            name = read_line(Some("Name: "))?;
        }
        let value = read_password(Some("Value: "))?;
        credentials.insert(name, value);
        let prompt = Some("Add more credentials (y/n)? ");
        if !read_flag(prompt)? {
            break;
        }
    }

    let secret = Secret::Credentials(credentials);
    let secret_meta = SecretMeta::new(label, secret.kind());
    let uuid = keeper.add(secret_meta, secret)?;
    keeper.vault().write_file(vault)?;
    info!(target: LOG_TARGET, "saved secret {}", uuid);
    Ok(())
}
