use std::{borrow::Cow, ffi::OsString};

use clap::{CommandFactory, Parser, Subcommand};

use terminal_banner::{Banner, Padding};

use secrecy::ExposeSecret;
use sos_core::{
    account::{AccountRef, DelegatedPassphrase},
    commit::SyncKind,
    passwd::diceware::generate_passphrase,
    secrecy,
    vault::{Vault, VaultRef},
};
use sos_node::client::provider::ProviderFactory;

use crate::{
    commands::{AccountCommand, FolderCommand, SecretCommand},
    helpers::{
        account::{switch, Owner, use_folder},
        readline::{read_flag, read_password},
    },
};

use crate::{Error, Result};

enum ConflictChoice {
    Push,
    Pull,
    Noop,
}

/// Secret storage shell.
#[derive(Parser, Debug)]
#[clap(name = "shell", author, version, about, long_about = None)]
struct Shell {
    #[clap(subcommand)]
    cmd: ShellCommand,
}

#[derive(Subcommand, Debug)]
enum ShellCommand {
    /// Renew session authentication.
    #[clap(alias = "auth")]
    Authenticate,
    /// Select a folder.
    Use {
        /// Folder name or id.
        folder: Option<VaultRef>,
    },
    /// Manage local accounts.
    #[clap(alias = "a")]
    Account {
        #[clap(subcommand)]
        cmd: AccountCommand,
    },
    /// Manage account folders.
    #[clap(alias = "f")]
    Folder {
        #[clap(subcommand)]
        cmd: FolderCommand,
    },
    /// Create edit and delete secrets.
    #[clap(alias = "s")]
    Secret {
        #[clap(subcommand)]
        cmd: SecretCommand,
    },

    /*
    /// Print commit status.
    Status {
        /// Print more information; include commit tree root hashes.
        #[clap(short, long)]
        verbose: bool,
    },
    /// Download changes from the remote server.
    Pull {
        /// Force a pull from the remote server.
        #[clap(short, long)]
        force: bool,
    },
    /// Upload changes to the remote server.
    Push {
        /// Force a push to the remote server.
        #[clap(short, long)]
        force: bool,
    },
    /// Change encryption password for the selected vault.
    #[clap(alias = "passwd")]
    Password,
    */

    /// Switch account.
    #[clap(alias = "su")]
    Switch {
        /// Account name or address.
        account: AccountRef,
    },
    /// Print the current identity.
    Whoami,
    /// Exit the shell.
    #[clap(alias = "q")]
    Quit,
}

/*
async fn maybe_conflict<F, R>(state: Owner, func: F) -> Result<()>
where
    F: FnOnce() -> R,
    R: futures::Future<Output = sos_node::client::Result<()>>,
{
    match func().await {
        Ok(_) => Ok(()),
        Err(e) => match e {
            sos_node::client::Error::Conflict {
                summary,
                local,
                remote,
            } => {
                let local_hex = local.0.to_string();
                let remote_hex = remote.0.to_string();
                let local_num = local.1;
                let remote_num = remote.1;

                let banner = Banner::new()
                    .padding(Padding::one())
                    .text(Cow::Borrowed("!!! CONFLICT !!!"))
                    .text(Cow::Owned(
                        format!("A conflict was detected on {}, proceed with caution; to resolve this conflict sync with the server.", summary.name()),
                    ))
                    .text(Cow::Owned(format!("local  = {}\nremote = {}", local_hex, remote_hex)))
                    .text(Cow::Owned(format!("local = #{}, remote = #{}", local_num, remote_num)))
                    .render();
                println!("{}", banner);

                let options = [
                    Choice(
                        "Pull remote changes from the server",
                        ConflictChoice::Pull,
                    ),
                    Choice(
                        "Push local changes to the server",
                        ConflictChoice::Push,
                    ),
                    Choice("None of the above", ConflictChoice::Noop),
                ];

                let prompt =
                    Some("Choose an action to resolve the conflict: ");
                let mut writer = state.write().await;
                match choose(prompt, &options)? {
                    Some(choice) => match choice {
                        ConflictChoice::Pull => {
                            writer.storage.pull(&summary, true).await?;
                            Ok(())
                        }
                        ConflictChoice::Push => {
                            writer.storage.push(&summary, true).await?;
                            Ok(())
                        }
                        ConflictChoice::Noop => Ok(()),
                    },
                    None => Ok(()),
                }
            }
            _ => Err(Error::from(e)),
        },
    }
}
*/

/// Execute the program command.
async fn exec_program(
    program: Shell,
    factory: ProviderFactory,
    state: Owner,
) -> Result<()> {
    match program.cmd {
        ShellCommand::Authenticate => {
            let mut writer = state.write().await;
            writer.storage.authenticate().await?;
            println!("session renewed ✓");
            Ok(())
        }
        ShellCommand::Account { cmd } => {
            let mut new_name: Option<String> = None;
            if let AccountCommand::Rename { name, .. } = &cmd {
                new_name = Some(name.to_owned());
            }

            crate::commands::account::run(cmd, factory).await?;

            if let Some(new_name) = new_name {
                let mut writer = state.write().await;
                writer.user.rename_account(new_name)?;
            }

            Ok(())
        }
        ShellCommand::Folder { cmd } => {
            crate::commands::folder::run(cmd, factory).await
        }
        ShellCommand::Secret { cmd } => {
            crate::commands::secret::run(cmd, factory).await
        }
        ShellCommand::Use { folder } => {
            use_folder(state, folder.as_ref()).await
        }

        /*
        ShellCommand::Status { verbose } => {
            let reader = state.read().await;
            let keeper =
                reader.storage.current().ok_or(Error::NoVaultSelected)?;
            let summary = keeper.summary().clone();
            drop(reader);

            let mut writer = state.write().await;
            let (status, pending_events) =
                writer.storage.status(&summary).await?;
            if verbose {
                let pair = status.pair();
                println!("local  = {}", pair.local.root_hex());
                println!("remote = {}", pair.remote.root_hex());
            }
            if let Some(pending_events) = pending_events {
                println!("{} event(s) have not been saved", pending_events);
            }
            println!("{}", status);
            Ok(())
        }
        ShellCommand::Pull { force } => {
            let mut writer = state.write().await;
            let keeper =
                writer.storage.current().ok_or(Error::NoVaultSelected)?;
            let summary = keeper.summary().clone();
            let result = writer.storage.pull(&summary, force).await?;
            match result.status {
                SyncKind::Equal => println!("Up to date"),
                SyncKind::Safe => {
                    if let Some(proof) = result.after {
                        println!("Pull complete {}", proof.root_hex());
                    }
                }
                SyncKind::Force => {
                    if let Some(proof) = result.after {
                        println!("Force pull complete {}", proof.root_hex());
                    }
                }
                SyncKind::Unsafe => {
                    println!("Cannot pull safely, use the --force option if you are sure.");
                }
            }
            Ok(())
        }
        ShellCommand::Push { force } => {
            let mut writer = state.write().await;
            let keeper =
                writer.storage.current().ok_or(Error::NoVaultSelected)?;
            let summary = keeper.summary().clone();
            let result = writer.storage.push(&summary, force).await?;
            match result.status {
                SyncKind::Equal => println!("Up to date"),
                SyncKind::Safe => {
                    if let Some(proof) = result.after {
                        println!("Push complete {}", proof.root_hex());
                    }
                }
                SyncKind::Force => {
                    if let Some(proof) = result.after {
                        println!("Force push complete {}", proof.root_hex());
                    }
                }
                SyncKind::Unsafe => {
                    println!("Cannot push safely, use the --force option if you are sure.");
                }
            }
            Ok(())
        }
        ShellCommand::Password => {
            let mut writer = state.write().await;
            let keeper =
                writer.storage.current_mut().ok_or(Error::NoVaultSelected)?;

            let banner = Banner::new()
                .padding(Padding::one())
                .text(Cow::Borrowed("!!! CHANGE PASSWORD !!!"))
                .text(Cow::Borrowed(
                    "Changing your password is a dangerous operation, your data may be corrupted if the process is interrupted.",
                ))
                .text(Cow::Borrowed(
                    "Vault change history will be deleted.",
                ))
                .text(Cow::Borrowed(
                    "A new encryption passphrase will be generated and shown on success; you must remember this new passphrase to access this vault.",
                ))
                .render();
            println!("{}", banner);

            let prompt = Some("Are you sure (y/n)? ");
            if read_flag(prompt)? {
                let passphrase = read_password(Some("Current passphrase: "))?;
                let (new_passphrase, _) = generate_passphrase()?;

                // Basic quick verification
                keeper
                    .verify(passphrase.clone())
                    .map_err(|_| Error::InvalidPassphrase)?;

                // We need a clone of the vault to avoid borrowing whilst
                // already mutably borrowed
                let vault: Vault = keeper.vault().clone();

                let new_passphrase = writer
                    .storage
                    .change_password(&vault, passphrase, new_passphrase)
                    .await?;

                drop(writer);

                let banner = Banner::new()
                    .padding(Padding::one())
                    .text(Cow::Borrowed("SUCCESS"))
                    .text(Cow::Borrowed(
                        "Your passphrase was changed successfully, your new passphrase is shown below.",
                    ))
                    .text(Cow::Borrowed(
                        "Ensure you remember this passphrase to access your vault.",
                    ))
                    .render();
                println!("{}", banner);

                let banner = Banner::new()
                    .padding(Padding::one())
                    .text(Cow::Borrowed("NEW ENCRYPTION PASSPHRASE"))
                    .text(Cow::Borrowed(new_passphrase.expose_secret()))
                    .render();
                println!("{}", banner);
            }

            Ok(())
        }
        */
        ShellCommand::Switch { account } => {
            let reader = state.read().await;
            let factory = reader.factory.clone();
            drop(reader);

            let state = switch(&account, factory).await?;
            let mut writer = state.write().await;

            // Ensure the vault summaries are loaded
            // so that "use" is effective immediately
            writer.storage.load_vaults().await?;

            Ok(())
        }
        ShellCommand::Whoami => {
            let reader = state.read().await;
            println!(
                "{} {}",
                reader.user.account().label(),
                reader.user.identity().address()
            );
            Ok(())
        }
        ShellCommand::Quit => {
            let mut writer = state.write().await;
            writer.user.sign_out();
            std::process::exit(0);
        }
    }
}

/// Intermediary to pretty print clap parse errors.
async fn exec_args<I, T>(
    it: I,
    factory: ProviderFactory,
    state: Owner,
) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match Shell::try_parse_from(it) {
        Ok(program) => exec_program(program, factory, state).await?,
        Err(e) => e.print().expect("unable to write error output"),
    }
    Ok(())
}

/// Execute a line of input in the context of the shell program.
pub async fn exec(
    line: &str,
    factory: ProviderFactory,
    state: Owner,
) -> Result<()> {
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
            exec_args(it, factory, state).await?;
        }
    }
    Ok(())
}
