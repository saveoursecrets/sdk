use crate::{
    helpers::{
        account::{
            list_accounts, new_account, resolve_account, resolve_user,
            verify, Owner, SHELL, USER,
        },
        messages::success,
        readline::read_flag,
    },
    Error, Result,
};
use clap::Subcommand;
use enum_iterator::all;
use sos_account::Account;
use sos_core::AccountRef;
use sos_migrate::import::{ImportFormat, ImportTarget};
use sos_vfs as vfs;
use std::{path::PathBuf, sync::Arc};

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Create an account.
    New {
        /// Name for the default folder.
        #[clap(long)]
        folder_name: Option<String>,

        /// Name for the new account.
        name: String,
    },
    /// List accounts.
    #[clap(alias = "ls")]
    List {
        /// Print more information.
        #[clap(short, long)]
        verbose: bool,
    },
    /// Print account information.
    Info {
        /// Print more information.
        #[clap(short, long)]
        verbose: bool,

        /// JSON output.
        #[clap(short, long)]
        json: bool,

        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,
    },
    /// Rename an account.
    Rename {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// New name for the account.
        name: String,
    },
    /// Export and import unencrypted secrets.
    Migrate {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        #[clap(subcommand)]
        cmd: MigrateCommand,
    },
    /// Export and import contacts (vCard).
    Contacts {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        #[clap(subcommand)]
        cmd: ContactsCommand,
    },
    /// Print search index statistics.
    #[clap(alias = "stats")]
    Statistics {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Print as JSON.
        #[clap(short, long)]
        json: bool,

        /// Show tag counts.
        #[clap(long)]
        tags: bool,

        /// Show folder counts.
        #[clap(short, long)]
        folders: bool,

        /// Show type counts.
        #[clap(short, long)]
        types: bool,
    },
    /// Delete an account.
    Delete {
        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,
    },
}

#[derive(Subcommand, Debug)]
pub enum MigrateCommand {
    /// Export unencrypted secrets to an archive.
    Export {
        /// Force overwrite of existing file.
        #[clap(long)]
        force: bool,

        /// Output file for the export.
        output: PathBuf,
    },
    /// Import unencrypted secrets.
    Import {
        /// Format of the file to import.
        #[clap(long)]
        format: ImportFormat,

        /// Name for the new folder.
        #[clap(short, long)]
        name: Option<String>,

        /// Input file to import.
        input: PathBuf,
    },
    /// Print available import formats.
    PrintImportFormats,
}

#[derive(Subcommand, Debug)]
pub enum ContactsCommand {
    /// Export all contacts to a vCard.
    Export {
        /// Force overwrite of existing file.
        #[clap(long)]
        force: bool,

        /// Output file for the export.
        output: PathBuf,
    },
    /// Import contacts from a vCard.
    Import {
        /// Input file to import.
        input: PathBuf,
    },
}

pub async fn run(cmd: Command) -> Result<()> {
    let is_shell = *SHELL.lock();
    match cmd {
        Command::New { name, folder_name } => {
            new_account(name, folder_name).await?;
        }
        Command::List { verbose } => {
            list_accounts(verbose).await?;
        }
        Command::Info {
            account,
            verbose,
            json,
        } => {
            account_info(account, verbose, json).await?;
        }
        Command::Rename { name, account } => {
            account_rename(account, name).await?;
            success("Account renamed");
        }
        Command::Migrate { account, cmd } => match cmd {
            MigrateCommand::Export { output, force } => {
                let user = resolve_user(account.as_ref(), false).await?;
                let exported = migrate_export(user, output, force).await?;
                if exported {
                    success("Account exported");
                }
            }
            MigrateCommand::Import {
                input,
                format,
                name,
            } => {
                let user = resolve_user(account.as_ref(), false).await?;
                migrate_import(user, input, format, name).await?;
                success("File imported");
            }
            MigrateCommand::PrintImportFormats => {
                for variant in all::<ImportFormat>() {
                    println!("{}", variant);
                }
            }
        },
        Command::Contacts { account, cmd } => {
            let user = resolve_user(account.as_ref(), false).await?;

            // Get the current folder so that the shell client
            // does not lose context when importing and exporting contacts
            let original_folder = {
                let owner = user.read().await;
                let owner = owner
                    .selected_account()
                    .ok_or(Error::NoSelectedAccount)?;

                let current = owner.current_folder().await?;

                let contacts = owner
                    .contacts_folder()
                    .await
                    .ok_or_else(|| Error::NoContactsFolder)?;
                owner.open_folder(contacts.id()).await?;
                current
            };

            match cmd {
                ContactsCommand::Export { output, force } => {
                    contacts_export(Arc::clone(&user), output, force).await?;
                    success("Contacts exported");
                    if let Some(folder) = original_folder {
                        let owner = user.read().await;
                        let owner = owner
                            .selected_account()
                            .ok_or(Error::NoSelectedAccount)?;
                        owner.open_folder(folder.id()).await?;
                    }
                }
                ContactsCommand::Import { input } => {
                    contacts_import(Arc::clone(&user), input).await?;
                    success("Contacts imported");
                    if let Some(folder) = original_folder {
                        let owner = user.read().await;
                        let owner = owner
                            .selected_account()
                            .ok_or(Error::NoSelectedAccount)?;
                        owner.open_folder(folder.id()).await?;
                    }
                }
            }
        }
        Command::Statistics {
            account,
            json,
            tags,
            folders,
            types,
        } => {
            let user = resolve_user(account.as_ref(), true).await?;
            let owner = user.read().await;
            let owner =
                owner.selected_account().ok_or(Error::NoSelectedAccount)?;
            let statistics = owner.statistics().await;

            if json {
                serde_json::to_writer_pretty(
                    &mut std::io::stdout(),
                    &statistics,
                )?;
                println!();
            } else {
                if tags && !statistics.tags.is_empty() {
                    println!("[TAGS]");
                    for (k, v) in &statistics.tags {
                        println!(" {}: {}", k, v);
                    }
                }

                if types && !statistics.types.is_empty() {
                    println!("[TYPES]");
                    for (k, v) in &statistics.types {
                        println!(" {}: {}", k, v);
                    }
                }

                if folders && !statistics.folders.is_empty() {
                    println!("[FOLDERS]");
                    for (s, v) in &statistics.folders {
                        println!(" {}: {}", s.name(), v);
                    }
                }

                println!("[INDEX]");
                println!(" Documents: {}", statistics.documents);
                println!(" Folders: {}", statistics.folders.len());
                println!(" Favorites: {}", statistics.favorites);
            }
        }
        Command::Delete { account } => {
            let deleted = account_delete(account).await?;
            if deleted {
                success("account deleted");
                if is_shell {
                    std::process::exit(0);
                }
            }
        }
    }

    Ok(())
}

/// Print account info.
async fn account_info(
    account: Option<AccountRef>,
    verbose: bool,
    json: bool,
) -> Result<()> {
    let user = resolve_user(account.as_ref(), false).await?;
    let owner = user.read().await;
    let owner = owner.selected_account().ok_or(Error::NoSelectedAccount)?;
    let data = owner.account_data().await?;

    if json {
        serde_json::to_writer_pretty(&mut std::io::stdout(), &data)?;
    } else {
        println!("{} {}", data.account.account_id(), data.account.label());
        for summary in &data.folders {
            if verbose {
                println!("{} {}", summary.id(), summary.name());
            } else {
                println!("{}", summary.name());
            }
        }
    }
    Ok(())
}

/// Rename an account.
async fn account_rename(
    account: Option<AccountRef>,
    name: String,
) -> Result<()> {
    let user = resolve_user(account.as_ref(), false).await?;
    let mut owner = user.write().await;
    let owner = owner
        .selected_account_mut()
        .ok_or(Error::NoSelectedAccount)?;
    owner.rename_account(name).await?;
    Ok(())
}

/// Delete an account.
async fn account_delete(account: Option<AccountRef>) -> Result<bool> {
    let is_shell = *SHELL.lock();
    let account = if !is_shell {
        // For deletion we don't accept account inference, it must
        // be specified explicitly
        account.as_ref().ok_or_else(|| Error::ExplicitAccount)?;

        resolve_account(account.as_ref())
            .await?
            .ok_or_else(|| Error::NoAccountFound)?
    } else {
        // Shell users can only delete their own account
        if account.is_some() {
            return Err(Error::NotShellAccount);
        }

        // Verify the password for shell users
        // before deletion
        verify(Arc::clone(&USER)).await?;

        let owner = USER.read().await;
        let owner =
            owner.selected_account().ok_or(Error::NoSelectedAccount)?;
        (&*owner).into()
    };

    let user = resolve_user(Some(&account), false).await?;
    let mut owner = user.write().await;
    let owner = owner
        .selected_account_mut()
        .ok_or(Error::NoSelectedAccount)?;

    let prompt = format!(
        r#"Delete account "{}" (y/n)? "#,
        owner.account_name().await?,
    );
    let result = if read_flag(Some(&prompt))? {
        owner.delete_account().await?;
        true
    } else {
        false
    };

    Ok(result)
}

/// Export a migration archive.
async fn migrate_export(
    user: Owner,
    output: PathBuf,
    force: bool,
) -> Result<bool> {
    if !force && vfs::try_exists(&output).await? {
        return Err(Error::FileExists(output));
    }

    let owner = user.read().await;
    let owner = owner.selected_account().ok_or(Error::NoSelectedAccount)?;

    let prompt = format!(
        r#"Export UNENCRYPTED account "{}" (y/n)? "#,
        owner.account_name().await?,
    );

    let result = if read_flag(Some(&prompt))? {
        owner.export_unsafe_archive(output).await?;
        true
    } else {
        false
    };

    Ok(result)
}

/// Import data from another app.
async fn migrate_import(
    user: Owner,
    input: PathBuf,
    format: ImportFormat,
    name: Option<String>,
) -> Result<()> {
    let target = ImportTarget {
        path: input,
        folder_name: name.unwrap_or_else(|| format.to_string()),
        format,
    };
    let mut owner = user.write().await;
    let owner = owner
        .selected_account_mut()
        .ok_or(Error::NoSelectedAccount)?;
    let _ = owner.import_file(target).await?;
    Ok(())
}

/// Export contacts to a vCard.
async fn contacts_export(
    user: Owner,
    output: PathBuf,
    force: bool,
) -> Result<()> {
    if !force && vfs::try_exists(&output).await? {
        return Err(Error::FileExists(output));
    }
    let owner = user.read().await;
    let owner = owner.selected_account().ok_or(Error::NoSelectedAccount)?;
    owner.export_all_contacts(output).await?;
    Ok(())
}

/// Import contacts from a vCard.
async fn contacts_import(user: Owner, input: PathBuf) -> Result<()> {
    let mut owner = user.write().await;
    let owner = owner
        .selected_account_mut()
        .ok_or(Error::NoSelectedAccount)?;
    let content = vfs::read_to_string(&input).await?;
    owner.import_contacts(&content, |_| {}).await?;
    Ok(())
}
