use std::{ffi::OsString, sync::Arc};

use clap::{CommandFactory, Parser, Subcommand};

use sos_net::{
    sdk::{account::AccountRef, vault::VaultRef},
};

use crate::{
    commands::{AccountCommand, CheckCommand, FolderCommand, SecretCommand},
    helpers::account::{cd_folder, switch, Owner},
};

use crate::Result;

/// Secret storage shell.
#[derive(Parser, Debug)]
#[clap(name = "shell", author, version, about, long_about = None)]
struct Shell {
    #[clap(subcommand)]
    cmd: ShellCommand,
}

#[derive(Subcommand, Debug)]
enum ShellCommand {
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
    /// Create, edit and delete secrets.
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
    /// Set a folder as the current working directory.
    Cd {
        /// Folder name or id.
        folder: Option<VaultRef>,
    },
    /// Switch account.
    #[clap(alias = "su")]
    Switch {
        /// Account name or address.
        account: AccountRef,
    },
    /// Check file status and integrity.
    Check {
        #[clap(subcommand)]
        cmd: CheckCommand,
    },
    /// Print the current identity.
    Whoami,
    /// Print the current folder.
    Pwd,
    /// Exit the shell.
    #[clap(alias = "q")]
    Quit,
}

/*
enum ConflictChoice {
    Push,
    Pull,
    Noop,
}
*/

/*
async fn maybe_conflict<F, R>(user: Owner, func: F) -> Result<()>
where
    F: FnOnce() -> R,
    R: futures::Future<Output = sos_net::client::Result<()>>,
{
    match func().await {
        Ok(_) => Ok(()),
        Err(e) => match e {
            sos_net::client::Error::Conflict {
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
                let mut owner = user.write().await;
                match choose(prompt, &options)? {
                    Some(choice) => match choice {
                        ConflictChoice::Pull => {
                            owner.storage.pull(&summary, true).await?;
                            Ok(())
                        }
                        ConflictChoice::Push => {
                            owner.storage.push(&summary, true).await?;
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
async fn exec_program(program: Shell, user: Owner) -> Result<()> {
    match program.cmd {
        ShellCommand::Account { cmd } => {
            let mut new_name: Option<String> = None;
            if let AccountCommand::Rename { name, .. } = &cmd {
                new_name = Some(name.to_owned());
            }

            crate::commands::account::run(cmd).await?;

            if let Some(new_name) = new_name {
                let mut owner = user.write().await;
                owner.user_mut().rename_account(new_name).await?;
            }

            Ok(())
        }
        ShellCommand::Folder { cmd } => {
            crate::commands::folder::run(cmd).await
        }
        ShellCommand::Secret { cmd } => {
            crate::commands::secret::run(cmd).await
        }
        ShellCommand::Cd { folder } => cd_folder(user, folder.as_ref()).await,

        /*
        ShellCommand::Status { verbose } => {
            let owner = user.read().await;
            let keeper =
                owner.storage.current().ok_or(Error::NoVaultSelected)?;
            let summary = keeper.summary().clone();
            drop(owner);

            let mut owner = user.write().await;
            let (status, pending_events) =
                owner.storage.status(&summary).await?;
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
            let mut owner = user.write().await;
            let keeper =
                owner.storage.current().ok_or(Error::NoVaultSelected)?;
            let summary = keeper.summary().clone();
            let result = owner.storage.pull(&summary, force).await?;
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
            let mut owner = user.write().await;
            let keeper =
                owner.storage.current().ok_or(Error::NoVaultSelected)?;
            let summary = keeper.summary().clone();
            let result = owner.storage.push(&summary, force).await?;
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
            let mut owner = user.write().await;
            let keeper =
                owner.storage.current_mut().ok_or(Error::NoVaultSelected)?;

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

                let new_passphrase = owner
                    .storage
                    .change_password(&vault, passphrase, new_passphrase)
                    .await?;

                drop(owner);

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
            let user = switch(&account).await?;

            // Try to select the default folder
            let default_folder = {
                let owner = user.read().await;
                owner.default_folder().await
            };
            if let Some(summary) = default_folder {
                let folder = Some(VaultRef::Id(*summary.id()));
                cd_folder(Arc::clone(&user), folder.as_ref()).await?;
            }

            Ok(())
        }
        ShellCommand::Check { cmd } => crate::commands::check::run(cmd).await,
        ShellCommand::Whoami => {
            let owner = user.read().await;
            println!(
                "{} {}",
                owner.user().account().label(),
                owner.user().identity().address()
            );
            Ok(())
        }
        ShellCommand::Pwd => {
            let owner = user.read().await;
            let storage = owner.storage();
            let reader = storage.read().await;
            if let Some(current) = reader.current() {
                println!(
                    "{} {}",
                    current.summary().name(),
                    current.summary().id(),
                );
            }
            Ok(())
        }
        ShellCommand::Quit => {
            let mut owner = user.write().await;
            owner.user_mut().sign_out();
            std::process::exit(0);
        }
    }
}

/// Intermediary to pretty print clap parse errors.
async fn exec_args<I, T>(it: I, user: Owner) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match Shell::try_parse_from(it) {
        Ok(program) => exec_program(program, user).await?,
        Err(e) => e.print().expect("unable to write error output"),
    }
    Ok(())
}

/// Execute a line of input in the context of the shell program.
pub async fn exec(line: &str, user: Owner) -> Result<()> {
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
            exec_args(it, user).await?;
        }
    }
    Ok(())
}
