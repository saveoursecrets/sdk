use std::{
    collections::HashMap,
    ffi::OsString,
    sync::{Arc, RwLock},
};

use clap::{CommandFactory, Parser, Subcommand};
use url::Url;

use sos_core::{
    diceware::generate,
    gatekeeper::Gatekeeper,
    operations::Payload,
    secret::{kind, Secret, SecretMeta, UuidOrName},
    vault::{encode, Summary, Vault},
};
use sos_readline::{
    read_flag, read_line, read_multiline, read_option, read_password,
};

use crate::{
    display_passphrase, run_blocking, Client, Error, Result, VaultInfo,
};

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
    Remove { vault: UuidOrName },
    /// Select a vault.
    Use { vault: UuidOrName },
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
        verbose: bool,
    },
    /// Add a secret.
    Add {
        #[clap(subcommand)]
        cmd: Add,
    },
    /// Print a secret.
    Get { secret: UuidOrName },
    /// Delete a secret.
    Del { secret: UuidOrName },
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
    Note { label: Option<String> },
    Credentials { label: Option<String> },
    Account { label: Option<String> },
    File { path: String },
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

    println!("### NOTE");
    println!("#");
    println!("# To abort the note enter Ctrl+C");
    println!("# To save the note enter Ctrl+D on a newline");
    println!("#");
    println!("###");

    if let Some(note) = read_multiline(None)? {
        let note = note.trim_end_matches('\n').to_string();
        let secret = Secret::Text(note);
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
        let secret = Secret::Credentials(credentials);
        let secret_meta = SecretMeta::new(label, secret.kind());
        Ok(Some((secret_meta, secret)))
    } else {
        Ok(None)
    }
}

fn add_account(label: Option<String>) -> Result<Option<(SecretMeta, Secret)>> {
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

fn add_file(path: String) -> Result<Option<(SecretMeta, Secret)>> {
    todo!()

    /*
    let file_path = PathBuf::from(&path)?;

    if !file.is_file() {
    }

    //let mut keeper = load_vault(&vault)?;
    //let vault_meta = unlock_vault(&mut keeper, false)?;
    //let meta_data = keeper.meta_data()?;

    let mime = if let Some(name) = file.file_name() {
        if let Some(name) = name.to_str() {
            mime_guess::from_path(name).first().map(|m| m.to_string())
        } else {
            None
        }
    } else {
        None
    };

    /*
    let mut label = if let Some(label) = label {
        label
    } else {
        file.file_name()
            .ok_or_else(|| anyhow!("not a valid filename"))
            .map(|name| name.to_string_lossy().into_owned())?
    };
    */

    let buffer = std::fs::read(file)?;
    let secret = Secret::Blob {
        buffer,
        mime,
        name: None,
    };
    let secret_meta = SecretMeta::new(label, secret.kind());
    Ok(Some((secret_meta, secret)))

    */
}

#[derive(Default)]
pub struct ShellState {
    /// Vaults managed by this signer.
    pub summaries: Vec<Summary>,
    /// Currently selected vault.
    pub current: Option<Gatekeeper>,
}

fn print_summaries_list(summaries: &[Summary]) -> Result<()> {
    for (index, summary) in summaries.iter().enumerate() {
        println!("{}) {} {}", index + 1, summary.name(), summary.id());
    }
    Ok(())
}

fn print_summary(summary: &Summary) -> Result<()> {
    println!(
        "Version {} using {} at #{}",
        summary.version(),
        summary.algorithm(),
        summary.change_seq()
    );
    println!("{} {}", summary.name(), summary.id());
    Ok(())
}

/// Execute the program command.
fn exec_program(
    program: Shell,
    client: Arc<Client>,
    state: Arc<RwLock<ShellState>>,
) -> Result<()> {
    match program.cmd {
        ShellCommand::Vaults => list_vaults(client, state, true)?,
        ShellCommand::Create { name } => {
            let (passphrase, _) = generate()?;
            let mut vault: Vault = Default::default();
            vault.set_name(name);
            vault.initialize(&passphrase)?;
            let buffer = encode(&vault)?;

            let response = run_blocking(client.create_vault(buffer))?;

            if !response.status().is_success() {
                return Err(Error::VaultCreate(response.status().into()));
            }
            display_passphrase(
                "Encryption passphrase",
                "YOU MUST REMEMBER THIS PASSPHRASE!",
                &passphrase,
            );

            list_vaults(client, state, false)?;
        }
        ShellCommand::Remove { vault } => {
            let mut writer = state.write().unwrap();
            let summary = match &vault {
                UuidOrName::Name(name) => {
                    writer.summaries.iter().find(|s| s.name() == name)
                }
                UuidOrName::Uuid(uuid) => {
                    writer.summaries.iter().find(|s| s.id() == uuid)
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
        ShellCommand::Use { vault } => {
            let mut writer = state.write().unwrap();
            let summary = match &vault {
                UuidOrName::Name(name) => {
                    writer.summaries.iter().find(|s| s.name() == name)
                }
                UuidOrName::Uuid(uuid) => {
                    writer.summaries.iter().find(|s| s.id() == uuid)
                }
            };

            if let Some(summary) = summary {
                let vault_bytes =
                    run_blocking(client.read_vault(summary.id()))?;
                let vault = Vault::read_buffer(vault_bytes)?;
                let mut keeper = Gatekeeper::new(vault);
                let password = read_password(Some("Passphrase: "))?;
                if let Ok(_) = keeper.unlock(&password) {
                    writer.current = Some(keeper);
                } else {
                    return Err(Error::VaultUnlockFail);
                }
            } else {
                return Err(Error::VaultNotAvailable(vault));
            }
        }
        ShellCommand::Info => {
            let reader = state.read().unwrap();
            if let Some(keeper) = &reader.current {
                let summary = keeper.summary();
                print_summary(summary)?;
            } else {
                return Err(Error::NoVaultSelected);
            }
        }
        ShellCommand::Seq => {
            let reader = state.read().unwrap();
            if let Some(keeper) = &reader.current {
                let local_change_seq = keeper.change_seq()?;
                let VaultInfo {
                    change_seq: remote_change_seq,
                } = run_blocking(client.head_vault(keeper.id()))?;
                println!(
                    "Local = {}, Remote = {}",
                    local_change_seq, remote_change_seq
                );
            } else {
                return Err(Error::NoVaultSelected);
            }
        }
        ShellCommand::Name { name } => {
            let mut writer = state.write().unwrap();
            let renamed = if let Some(keeper) = writer.current.as_mut() {
                if let Some(name) = name {
                    keeper.set_vault_name(name.clone())?;
                    let response = run_blocking(client.set_vault_name(
                        keeper.id(),
                        keeper.change_seq()?,
                        &name,
                    ))?;
                    if !response.status().is_success() {
                        return Err(Error::SetVaultName(
                            response.status().into(),
                        ));
                    }
                    true
                } else {
                    let name = run_blocking(client.vault_name(keeper.id()))?;
                    println!("{}", name);
                    false
                }
            } else {
                return Err(Error::NoVaultSelected);
            };

            if renamed {
                drop(writer);
                list_vaults(client, state, false)?;
            }
        }
        ShellCommand::Keys => {
            let reader = state.read().unwrap();
            if let Some(keeper) = &reader.current {
                for uuid in keeper.vault().keys() {
                    println!("{}", uuid);
                }
            } else {
                return Err(Error::NoVaultSelected);
            }
        }
        ShellCommand::List { verbose } => {
            let reader = state.read().unwrap();
            if let Some(keeper) = &reader.current {
                for (index, uuid) in keeper.vault().keys().enumerate() {
                    if let Some((secret_meta, _, _)) = keeper.read(uuid)? {
                        let label = secret_meta.label();
                        let short_name = secret_meta.short_name();
                        print!("[{}] ", short_name);

                        if verbose {
                            println!("{} {}", label, uuid);
                        } else {
                            println!("{}", label);
                        }
                    } else {
                        return Err(Error::SecretNotAvailable(
                            UuidOrName::Uuid(*uuid),
                        ));
                    }
                }
            } else {
                return Err(Error::NoVaultSelected);
            }
        }
        ShellCommand::Add { cmd } => {
            let mut writer = state.write().unwrap();
            if let Some(keeper) = writer.current.as_mut() {
                let change_seq = keeper.change_seq()?;
                let id = *keeper.id();
                let result = match cmd {
                    Add::Note { label } => add_note(label)?,
                    Add::Credentials { label } => add_credentials(label)?,
                    Add::Account { label } => add_account(label)?,
                    Add::File { path } => add_file(path)?,
                };

                if let Some((secret_meta, secret)) = result {
                    if let Payload::CreateSecret(
                        change_seq,
                        secret_id,
                        encrypted,
                    ) = keeper.create(secret_meta, secret)?
                    {
                        let response = run_blocking(client.create_secret(
                            &id,
                            &secret_id,
                            encrypted.as_ref(),
                            change_seq,
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
                        println!(
                            "[{}] {}",
                            Secret::type_name(*secret_meta.kind()),
                            secret_meta.label()
                        );
                        println!("{:#?}", secret_data);

                        run_blocking(client.read_secret(
                            keeper.change_seq()?,
                            keeper.id(),
                            uuid,
                        ))?;
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
                            run_blocking(client.delete_secret(
                                *payload.change_seq().unwrap(),
                                keeper.id(),
                                &uuid,
                            ))?;
                        } else {
                            return Err(Error::SecretNotAvailable(secret));
                        }
                    }
                }
            } else {
                return Err(Error::SecretNotAvailable(secret));
            }
        }
        ShellCommand::Whoami => {
            let address = client.address()?;
            println!("{}", address);
        }
        ShellCommand::Close => {
            let mut writer = state.write().unwrap();
            writer.current = None;
        }
        ShellCommand::Quit => {
            std::process::exit(0);
        }
    }
    Ok(())
}

/// Intermediary to pretty print clap parse errors.
fn exec_args<I, T>(
    it: I,
    client: Arc<Client>,
    state: Arc<RwLock<ShellState>>,
) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match Shell::try_parse_from(it) {
        Ok(program) => exec_program(program, client, state)?,
        Err(e) => e.print().expect("unable to write error output"),
    }
    Ok(())
}

/// Exposed so that the shell program can automatically
/// try to list vaults after creating a signer.
pub fn list_vaults(
    client: Arc<Client>,
    state: Arc<RwLock<ShellState>>,
    print: bool,
) -> Result<()> {
    let summaries = run_blocking(client.list_vaults())?;
    if print {
        print_summaries_list(&summaries)?;
    }
    let mut writer = state.write().unwrap();
    writer.summaries = summaries;
    Ok(())
}

/// Execute a line of input in the context of the shell program.
pub fn exec(
    line: &str,
    client: Arc<Client>,
    state: Arc<RwLock<ShellState>>,
) -> Result<()> {
    let prefixed = format!("sos-shell {}", line);
    let it = prefixed.split_ascii_whitespace();
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
        exec_args(it, client, state)?;
    }
    Ok(())
}
