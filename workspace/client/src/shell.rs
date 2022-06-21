use std::{
    collections::HashMap,
    ffi::OsString,
    sync::{Arc, RwLock},
};

use clap::{CommandFactory, Parser, Subcommand};
use thiserror::Error;

use sos_core::{
    diceware::generate,
    gatekeeper::Gatekeeper,
    operations::Payload,
    secret::{kind, Secret, SecretMeta, UuidOrName},
    vault::{encode, Summary, Vault},
};
use sos_readline::{read_flag, read_line, read_multiline, read_password};

use crate::{display_passphrase, run_blocking, Client, Result, VaultInfo};

#[derive(Debug, Error)]
pub enum ShellError {
    #[error(r#"vault "{0}" not found, run "vaults" to load the vault list"#)]
    VaultNotAvailable(UuidOrName),

    #[error("failed to unlock vault")]
    VaultUnlockFail,

    #[error(r#"no vault selected, run "use" to select a vault"#)]
    NoVaultSelected,

    #[error(r#"secret "{0}" not found"#)]
    SecretNotAvailable(UuidOrName),

    #[error("failed to create vault, got status code {0}")]
    VaultCreate(u16),

    #[error("failed to delete vault, got status code {0}")]
    VaultRemove(u16),

    #[error("failed to set vault name, got status code {0}")]
    SetVaultName(u16),

    #[error("failed to add secret, got status code {0}")]
    AddSecret(u16),

    #[error(transparent)]
    Clap(#[from] clap::Error),

    #[error(transparent)]
    Core(#[from] sos_core::Error),

    #[error(transparent)]
    Client(#[from] crate::Error),

    #[error(transparent)]
    Readline(#[from] sos_readline::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

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
    List,
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
            eprintln!("name '{}' already exists", &name);
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
) -> std::result::Result<(), ShellError> {
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
                return Err(ShellError::VaultCreate(response.status().into()));
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
                        return Err(ShellError::VaultRemove(
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
                return Err(ShellError::VaultNotAvailable(vault));
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
                    return Err(ShellError::VaultUnlockFail);
                }
            } else {
                return Err(ShellError::VaultNotAvailable(vault));
            }
        }
        ShellCommand::Info => {
            let reader = state.read().unwrap();
            if let Some(keeper) = &reader.current {
                let summary = keeper.summary();
                print_summary(summary)?;
            } else {
                return Err(ShellError::NoVaultSelected);
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
                return Err(ShellError::NoVaultSelected);
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
                        return Err(ShellError::SetVaultName(
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
                return Err(ShellError::NoVaultSelected);
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
                return Err(ShellError::NoVaultSelected);
            }
        }
        ShellCommand::List => {
            let reader = state.read().unwrap();
            if let Some(keeper) = &reader.current {
                for (index, uuid) in keeper.vault().keys().enumerate() {
                    if let Some((secret_meta, _, _)) = keeper.read(uuid)? {
                        println!(
                            "{}) {}",
                            index + 1,
                            secret_meta.label(),
                            //Secret::type_name(*secret_meta.kind()),
                        );
                    } else {
                        return Err(ShellError::SecretNotAvailable(
                            UuidOrName::Uuid(*uuid),
                        ));
                    }
                }
            } else {
                return Err(ShellError::NoVaultSelected);
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
                            return Err(ShellError::AddSecret(
                                response.status().into(),
                            ));
                        }
                    } else {
                        unreachable!("unexpected payload for create secret");
                    }
                }
            } else {
                return Err(ShellError::NoVaultSelected);
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
                        return Err(ShellError::SecretNotAvailable(secret));
                    }
                } else {
                    return Err(ShellError::SecretNotAvailable(secret));
                }
            } else {
                return Err(ShellError::NoVaultSelected);
            }
        }
        ShellCommand::Del { secret } => {
            let reader = state.read().unwrap();
            let uuid = if let Some(keeper) = &reader.current {
                let meta_data = keeper.meta_data()?;
                if let Some((uuid, _)) =
                    keeper.find_by_uuid_or_label(&meta_data, &secret)
                {
                    Some(*uuid)
                } else {
                    None
                }
            } else {
                return Err(ShellError::NoVaultSelected);
            };
            drop(reader);

            if let Some(uuid) = uuid {
                let mut writer = state.write().unwrap();
                if let Some(keeper) = writer.current.as_mut() {
                    if let Some(payload) = keeper.delete(&uuid)? {
                        run_blocking(client.delete_secret(
                            *payload.change_seq().unwrap(),
                            keeper.id(),
                            &uuid,
                        ))?;
                    } else {
                        return Err(ShellError::SecretNotAvailable(secret));
                    }
                }
            } else {
                return Err(ShellError::SecretNotAvailable(secret));
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
) -> std::result::Result<(), ShellError>
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
) -> std::result::Result<(), ShellError> {
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
) -> std::result::Result<(), ShellError> {
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
