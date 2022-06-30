use std::{
    borrow::Cow,
    collections::HashMap,
    ffi::OsString,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use clap::{CommandFactory, Parser, Subcommand};

use terminal_banner::{Banner, Padding};
use url::Url;

use sos_core::{
    diceware::generate,
    gatekeeper::Gatekeeper,
    secret::{Secret, SecretMeta, SecretRef},
    vault::{encode, Vault, VaultAccess},
};
use sos_readline::{
    read_flag, read_line, read_line_allow_empty, read_multiline, read_option,
    read_password,
};

use crate::{display_passphrase, run_blocking, Cache, Error, Result};

mod editor;
mod print;

/// Secret storage shell.
#[derive(Parser, Debug)]
#[clap(name = "sos-shell", author, version, about, long_about = None)]
struct Shell {
    #[clap(subcommand)]
    cmd: ShellCommand,
}

#[derive(Subcommand, Debug)]
enum ShellCommand {
    /// List vaults.
    Vaults,
    /// Create a new vault.
    Create { name: String },
    /// Delete a vault.
    Remove { vault: SecretRef },
    /// Select a vault.
    Use { vault: SecretRef },
    /// Print information about the selected vault.
    Info,
    /// Get or set the name of the selected vault.
    Name { name: Option<String> },
    /// Print local and remote change sequences.
    Seq,
    /// Print secret keys for the selected vault.
    Keys,
    /// List secrets for the selected vault.
    #[clap(alias = "ls")]
    List {
        /// Print more information
        #[clap(short, long)]
        long: bool,
    },
    /// Add a secret.
    Add {
        #[clap(subcommand)]
        cmd: Add,
    },
    /// Print a secret.
    Get { secret: SecretRef },
    /// Update a secret.
    Set { secret: SecretRef },
    /// Delete a secret.
    Del { secret: SecretRef },
    /// Rename a secret.
    Mv {
        secret: SecretRef,
        label: Option<String>,
    },
    /// Print the current identity.
    Whoami,
    /// Close the selected vault.
    Close,
    /// Exit the shell.
    #[clap(alias = "q")]
    Quit,
}

#[derive(Subcommand, Debug)]
enum Add {
    /// Add a note.
    Note { label: Option<String> },
    /// Add a list of credentials.
    List { label: Option<String> },
    /// Add an account password.
    Account { label: Option<String> },
    /// Add a file.
    File { path: String, label: Option<String> },
}

fn get_label(label: Option<String>) -> Result<String> {
    if let Some(label) = label {
        Ok(label)
    } else {
        Ok(read_line(Some("Label: "))?)
    }
}

fn add_note(label: Option<String>) -> Result<Option<(SecretMeta, Secret)>> {
    let label = get_label(label)?;
    let banner = Banner::new()
        .padding(Padding::one())
        .text(Cow::Owned(format!("[NOTE] {}", label)))
        .text(Cow::Borrowed(
            r#"To abort the note enter Ctrl+C
To save the note enter Ctrl+D on a newline"#,
        ))
        .render();
    println!("{}", banner);

    if let Some(note) = read_multiline(None)? {
        let note = note.trim_end_matches('\n').to_string();
        let secret = Secret::Note(note);
        let secret_meta = SecretMeta::new(label, secret.kind());
        Ok(Some((secret_meta, secret)))
    } else {
        Ok(None)
    }
}

fn add_credentials(
    label: Option<String>,
) -> Result<Option<(SecretMeta, Secret)>> {
    let label = get_label(label)?;

    let mut credentials: HashMap<String, String> = HashMap::new();
    loop {
        let mut name = read_line(Some("Name: "))?;
        while credentials.get(&name).is_some() {
            tracing::error!("name '{}' already exists", &name);
            name = read_line(Some("Name: "))?;
        }
        let value = read_password(Some("Value: "))?;
        credentials.insert(name, value);
        let prompt = Some("Add more credentials (y/n)? ");
        if !read_flag(prompt)? {
            break;
        }
    }

    if !credentials.is_empty() {
        let secret = Secret::List(credentials);
        let secret_meta = SecretMeta::new(label, secret.kind());
        Ok(Some((secret_meta, secret)))
    } else {
        Ok(None)
    }
}

fn add_account(
    label: Option<String>,
) -> Result<Option<(SecretMeta, Secret)>> {
    let label = get_label(label)?;

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
    Ok(Some((secret_meta, secret)))
}

fn add_file(
    path: String,
    label: Option<String>,
) -> Result<Option<(SecretMeta, Secret)>> {
    let file = PathBuf::from(&path);

    let name = if let Some(name) = file.file_name() {
        name.to_string_lossy().into_owned()
    } else {
        return Err(Error::FileName(file));
    };

    let mut label = if let Some(label) = label {
        label
    } else {
        read_line_allow_empty(Some("Label: "))?
    };

    if label.is_empty() {
        label = name.clone();
    }

    let secret = read_file_secret(&path)?;
    let secret_meta = SecretMeta::new(label, secret.kind());
    Ok(Some((secret_meta, secret)))
}

fn read_file_secret(path: &str) -> Result<Secret> {
    let file = PathBuf::from(path);

    if !file.is_file() {
        return Err(Error::NotFile(file));
    }

    let name = if let Some(name) = file.file_name() {
        name.to_string_lossy().into_owned()
    } else {
        return Err(Error::FileName(file));
    };

    let mime = mime_guess::from_path(&name)
        .first()
        .map(|m| m.to_string())
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let buffer = std::fs::read(file)?;
    Ok(Secret::File { name, mime, buffer })
}

/// Execute the program command.
fn exec_program(program: Shell, cache: Arc<RwLock<Cache>>) -> Result<()> {
    match program.cmd {
        ShellCommand::Vaults => list_vaults(cache, true)?,
        ShellCommand::Create { name } => {
            let reader = cache.read().unwrap();
            let (passphrase, _) = generate()?;
            let mut vault: Vault = Default::default();
            vault.set_name(name);
            vault.initialize(&passphrase)?;
            let buffer = encode(&vault)?;

            let response =
                run_blocking(reader.client().create_vault(buffer))?;

            if !response.status().is_success() {
                return Err(Error::VaultCreate(response.status().into()));
            }
            display_passphrase("ENCRYPTION PASSPHRASE", &passphrase);

            drop(reader);
            list_vaults(cache, false)?;
        }
        ShellCommand::Use { vault } => {
            let reader = cache.read().unwrap();
            let summary = reader.find_summary(&vault).map(|s| s.clone());
            drop(reader);
            if let Some(summary) = &summary {
                let mut writer = cache.write().unwrap();
                let vault = run_blocking(writer.load_vault(summary))?;
                let mut keeper = Gatekeeper::new(vault);
                let password = read_password(Some("Passphrase: "))?;
                if let Ok(_) = keeper.unlock(&password) {
                    writer.set_current(Some(keeper));
                } else {
                    return Err(Error::VaultUnlockFail);
                }
            } else {
                return Err(Error::VaultNotAvailable(vault));
            }
        }
        ShellCommand::Info => {
            let reader = cache.read().unwrap();
            if let Some(keeper) = reader.current() {
                let summary = keeper.summary();
                println!("{}", summary);
            } else {
                return Err(Error::NoVaultSelected);
            }
        }
        ShellCommand::Keys => {
            let reader = cache.read().unwrap();
            if let Some(keeper) = reader.current() {
                for uuid in keeper.vault().keys() {
                    println!("{}", uuid);
                }
            } else {
                return Err(Error::NoVaultSelected);
            }
        }
        ShellCommand::List { long } => {
            let reader = cache.read().unwrap();
            if let Some(keeper) = reader.current() {
                let meta = keeper.meta_data()?;
                for (uuid, secret_meta) in meta {
                    let label = secret_meta.label();
                    let short_name = secret_meta.short_name();
                    print!("[{}] ", short_name);
                    if long {
                        println!("{} {}", label, uuid);
                    } else {
                        println!("{}", label);
                    }
                }
            } else {
                return Err(Error::NoVaultSelected);
            }
        }
        ShellCommand::Name { name } => {
            let mut writer = cache.write().unwrap();
            let (renamed, summary, name) =
                if let Some(keeper) = writer.current_mut() {
                    if let Some(name) = name {
                        keeper.set_vault_name(name.clone())?;
                        (true, keeper.summary().clone(), name.to_string())
                    } else {
                        let name = keeper.name();
                        println!("{}", name);
                        (false, keeper.summary().clone(), name.to_string())
                    }
                } else {
                    return Err(Error::NoVaultSelected);
                };

            if renamed {
                run_blocking(writer.set_vault_name(&summary, &name))?;
                drop(writer);
                list_vaults(cache, false)?;
            }
        }

        /*
        ShellCommand::Remove { vault } => {
            let mut writer = state.write().unwrap();
            let summary = match &vault {
                SecretRef::Name(name) => {
                    writer.summaries.iter().find(|s| s.name() == name)
                }
                SecretRef::Id(id) => {
                    writer.summaries.iter().find(|s| s.id() == id)
                }
            };

            if let Some(summary) = summary {
                let prompt = format!(
                    r#"Permanently delete vault "{}" (y/n)? "#,
                    summary.name()
                );
                let removed = if read_flag(Some(&prompt))? {
                    let response =
                        run_blocking(client.delete_vault(summary.id()))?;
                    if !response.status().is_success() {
                        return Err(Error::VaultRemove(
                            response.status().into(),
                        ));
                    }

                    // If the deleted vault is the currently selected
                    // vault we must clear the selection
                    let id = writer.current.as_ref().map(|c| c.id());
                    if let Some(id) = id {
                        if id == summary.id() {
                            writer.current = None;
                        }
                    }

                    true
                } else {
                    false
                };

                if removed {
                    drop(writer);
                    list_vaults(client, state, false)?;
                }
            } else {
                return Err(Error::VaultNotAvailable(vault));
            }
        }
        ShellCommand::Seq => {
            let reader = state.read().unwrap();
            if let Some(keeper) = &reader.current {
                todo!();

                /*
                let VaultInfo {
                    change_seq: remote_change_seq,
                } = run_blocking(client.head_vault(keeper.id()))?;
                println!(
                    "Local = {}, Remote = {}",
                    local_change_seq, remote_change_seq
                );
                */
            } else {
                return Err(Error::NoVaultSelected);
            }
        }
        ShellCommand::Add { cmd } => {
            let mut writer = state.write().unwrap();
            if let Some(keeper) = writer.current.as_mut() {
                let id = *keeper.id();
                let result = match cmd {
                    Add::Note { label } => add_note(label)?,
                    Add::List { label } => add_credentials(label)?,
                    Add::Account { label } => add_account(label)?,
                    Add::File { path, label } => add_file(path, label)?,
                };

                if let Some((secret_meta, secret)) = result {
                    if let SyncEvent::CreateSecret(secret_id, encrypted) =
                        keeper.create(secret_meta, secret)?
                    {
                        let response = run_blocking(client.create_secret(
                            &id,
                            &secret_id,
                            encrypted.as_ref(),
                        ))?;

                        if !response.status().is_success() {
                            return Err(Error::AddSecret(
                                response.status().into(),
                            ));
                        }
                    } else {
                        unreachable!("unexpected payload for create secret");
                    }
                }
            } else {
                return Err(Error::NoVaultSelected);
            }
        }
        ShellCommand::Get { secret } => {
            let reader = state.read().unwrap();
            if let Some(keeper) = &reader.current {
                let meta_data = keeper.meta_data()?;
                if let Some((uuid, _)) =
                    keeper.find_by_uuid_or_label(&meta_data, &secret)
                {
                    if let Some((secret_meta, secret_data, payload)) =
                        keeper.read(uuid)?
                    {
                        print::secret(&secret_meta, &secret_data);

                        run_blocking(client.read_secret(keeper.id(), uuid))?;
                    } else {
                        return Err(Error::SecretNotAvailable(secret));
                    }
                } else {
                    return Err(Error::SecretNotAvailable(secret));
                }
            } else {
                return Err(Error::NoVaultSelected);
            }
        }
        ShellCommand::Set { secret } => {
            let reader = state.read().unwrap();
            let result = if let Some(keeper) = &reader.current {
                let meta_data = keeper.meta_data()?;
                if let Some((uuid, _)) =
                    keeper.find_by_uuid_or_label(&meta_data, &secret)
                {
                    if let Some((secret_meta, secret, _)) =
                        keeper.read(uuid)?
                    {
                        Some((*uuid, secret_meta, secret))
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                return Err(Error::NoVaultSelected);
            };
            drop(reader);

            if let Some((uuid, secret_meta, secret_data)) = result {
                let result = if let Secret::File { name, mime, buffer } =
                    &secret_data
                {
                    if mime.starts_with("text/") {
                        editor::edit(&secret_data)?
                    } else {
                        println!(
                            "Binary {} {} {}",
                            name,
                            mime,
                            human_bytes(buffer.len() as f64)
                        );
                        let file_path = read_line(Some("File path: "))?;
                        Cow::Owned(read_file_secret(&file_path)?)
                    }
                } else {
                    editor::edit(&secret_data)?
                };

                if let Cow::Owned(edited_secret) = result {
                    let mut writer = state.write().unwrap();
                    if let Some(keeper) = writer.current.as_mut() {
                        let vault_id = *keeper.id();

                        if let Some(payload) = keeper.update(
                            &uuid,
                            secret_meta,
                            edited_secret,
                        )? {
                            if let SyncEvent::UpdateSecret(uuid, value) =
                                payload
                            {
                                let response =
                                    run_blocking(client.update_secret(
                                        &vault_id, &uuid, &*value,
                                    ))?;
                                if !response.status().is_success() {
                                    return Err(Error::SetSecret(
                                        response.status().into(),
                                    ));
                                }
                            } else {
                                unreachable!(
                                    "expected update secret payload"
                                );
                            }
                        } else {
                            return Err(Error::SecretNotAvailable(secret));
                        }
                    }
                }
            } else {
                return Err(Error::SecretNotAvailable(secret));
            }
        }
        ShellCommand::Del { secret } => {
            let reader = state.read().unwrap();
            let result = if let Some(keeper) = &reader.current {
                let meta_data = keeper.meta_data()?;
                if let Some((uuid, secret_meta)) =
                    keeper.find_by_uuid_or_label(&meta_data, &secret)
                {
                    Some((*uuid, secret_meta.clone()))
                } else {
                    None
                }
            } else {
                return Err(Error::NoVaultSelected);
            };
            drop(reader);

            if let Some((uuid, secret_meta)) = result {
                let prompt =
                    format!(r#"Delete "{}" (y/n)? "#, secret_meta.label());
                if read_flag(Some(&prompt))? {
                    let mut writer = state.write().unwrap();
                    if let Some(keeper) = writer.current.as_mut() {
                        if let Some(payload) = keeper.delete(&uuid)? {
                            run_blocking(
                                client.delete_secret(keeper.id(), &uuid),
                            )?;
                        } else {
                            return Err(Error::SecretNotAvailable(secret));
                        }
                    }
                }
            } else {
                return Err(Error::SecretNotAvailable(secret));
            }
        }
        ShellCommand::Mv { secret, label } => {
            let reader = state.read().unwrap();
            let result = if let Some(keeper) = &reader.current {
                let meta_data = keeper.meta_data()?;
                if let Some((uuid, secret_meta)) =
                    keeper.find_by_uuid_or_label(&meta_data, &secret)
                {
                    if let (Some(value), _) = keeper.vault().read(uuid)? {
                        let VaultCommit(
                            _,
                            VaultEntry(meta_aead, secret_aead),
                        ) = value.as_ref().clone();
                        Some((*uuid, meta_aead, secret_aead))
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                return Err(Error::NoVaultSelected);
            };
            drop(reader);

            if let Some((uuid, meta_aead, secret_aead)) = result {
                let mut writer = state.write().unwrap();
                if let Some(keeper) = writer.current.as_mut() {
                    let label = get_label(label)?;
                    let vault_id = *keeper.id();

                    let mut secret_meta = keeper.decrypt_meta(&meta_aead)?;
                    secret_meta.set_label(label);
                    let meta_aead = keeper.encrypt_meta(&secret_meta)?;

                    let (commit, _) =
                        Vault::commit_hash(&meta_aead, &secret_aead)?;

                    if let Some(payload) = keeper.vault_mut().update(
                        &uuid,
                        commit,
                        VaultEntry(meta_aead, secret_aead),
                    )? {
                        if let SyncEvent::UpdateSecret(uuid, value) = payload
                        {
                            let response = run_blocking(
                                client
                                    .update_secret(&vault_id, &uuid, &*value),
                            )?;
                            if !response.status().is_success() {
                                return Err(Error::SetSecret(
                                    response.status().into(),
                                ));
                            }
                        } else {
                            unreachable!("expected update secret payload");
                        }
                    } else {
                        return Err(Error::SecretNotAvailable(secret));
                    }
                } else {
                    return Err(Error::NoVaultSelected);
                }
            } else {
                return Err(Error::SecretNotAvailable(secret));
            }
        }
        */
        ShellCommand::Whoami => {
            let reader = cache.read().unwrap();
            let address = reader.client().address()?;
            println!("{}", address);
        }
        ShellCommand::Close => {
            let mut writer = cache.write().unwrap();
            if let Some(current) = writer.current_mut() {
                current.lock();
            }
            writer.set_current(None);
        }
        ShellCommand::Quit => {
            std::process::exit(0);
        }

        /////////////////////////////////////////////////////
        _ => todo!(),
        /////////////////////////////////////////////////////
    }
    Ok(())
}

/// Intermediary to pretty print clap parse errors.
fn exec_args<I, T>(it: I, cache: Arc<RwLock<Cache>>) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match Shell::try_parse_from(it) {
        Ok(program) => exec_program(program, cache)?,
        Err(e) => e.print().expect("unable to write error output"),
    }
    Ok(())
}

/// Exposed so that the shell program can automatically
/// try to list vaults after creating a signer.
pub fn list_vaults(cache: Arc<RwLock<Cache>>, print: bool) -> Result<()> {
    let mut writer = cache.write().unwrap();
    let summaries = run_blocking(writer.load_summaries())?;
    if print {
        print::summaries_list(&summaries);
    }
    Ok(())
}

/// Execute a line of input in the context of the shell program.
pub fn exec(line: &str, cache: Arc<RwLock<Cache>>) -> Result<()> {
    if !line.trim().is_empty() {
        let mut sanitized = shell_words::split(line.trim_end_matches(' '))?;
        sanitized.insert(0, String::from("sos-shell"));
        let it = sanitized.into_iter();
        let mut cmd = Shell::command();
        if line == "-V" {
            let version = cmd.render_version();
            print!("{}", version);
        } else if line == "version" || line == "--version" {
            let version = cmd.render_long_version();
            print!("{}", version);
        } else if line == "-h" {
            cmd.print_help()?;
        } else if line == "help" || line == "--help" {
            cmd.print_long_help()?;
        } else {
            exec_args(it, cache)?;
        }
    }
    Ok(())
}
