use std::sync::{Arc, RwLock};

use clap::{CommandFactory, Parser, Subcommand};
use std::future::Future;
use thiserror::Error;
use tokio::runtime::Runtime;

use sos_core::{
    gatekeeper::Gatekeeper,
    secret::Secret,
    secret::UuidOrName,
    vault::{Summary, Vault},
};
use sos_readline::read_password;

use crate::{Client, Result};

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
    /// Select a vault.
    Use { vault: UuidOrName },
    /// Print information about the selected vault.
    Info,
    /// Print secret keys for the selected vault.
    Keys,
    /// List secrets for the selected vault.
    #[clap(alias = "ls")]
    List,
    /// Print a secret.
    Get { secret: UuidOrName },
    /// Print the current identity.
    Whoami,
    /// Close the selected vault.
    Close,
    /// Exit the shell.
    #[clap(alias = "q")]
    Quit,
}

#[derive(Default)]
pub struct ShellState {
    /// Vaults managed by this signer.
    pub summaries: Vec<Summary>,
    /// Currently selected vault.
    pub current: Option<Gatekeeper>,
}

/// Runs a future blocking the current thread so we can
/// merge the synchronous nature of the shell prompt with the
/// asynchronous API exposed by the client.
fn run_blocking<F, R>(func: F) -> Result<R>
where
    F: Future<Output = Result<R>> + Send,
    R: Send,
{
    Ok(Runtime::new().unwrap().block_on(func)?)
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

pub fn run_shell_command(
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
        match Shell::try_parse_from(it) {
            Ok(args) => match args.cmd {
                ShellCommand::Vaults => list_vaults(client, state, true)?,
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
                            run_blocking(client.load_vault(summary.id()))?;
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
                            if let Some((secret_meta, _, _)) =
                                keeper.read(uuid)?
                            {
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
                ShellCommand::Get { secret } => {
                    let reader = state.read().unwrap();
                    if let Some(keeper) = &reader.current {
                        let meta_data = keeper.meta_data()?;
                        if let Some((uuid, _)) =
                            keeper.find_by_uuid_or_label(&meta_data, &secret)
                        {
                            if let Some((secret_meta, secret_data, _)) =
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
                                return Err(ShellError::SecretNotAvailable(
                                    secret,
                                ));
                            }
                        } else {
                            return Err(ShellError::SecretNotAvailable(secret));
                        }
                    } else {
                        return Err(ShellError::NoVaultSelected);
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
            },
            Err(e) => e.print().expect("unable to write error output"),
        }
    }
    Ok(())
}
