use clap::Subcommand;
use std::{path::PathBuf, sync::Arc};

use sos_net::{
    client::NetworkAccount,
    sdk::{
        account::archive::{
            AccountBackup, ExtractFilesLocation, Inventory, RestoreOptions,
        },
        identity::{AccountRef, PublicIdentity},
        migrate::import::{ImportFormat, ImportTarget},
        vfs, Paths,
    },
};

use crate::{
    helpers::{
        account::{
            find_account, list_accounts, new_account, resolve_account,
            resolve_user, sign_in, verify, Owner, USER,
        },
        readline::read_flag,
    },
    Error, Result, TARGET,
};

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
    /// Create secure backup as a zip archive.
    Backup {
        /// Output zip archive.
        #[clap(short, long)]
        output: PathBuf,

        /// Force overwrite of existing file.
        #[clap(long)]
        force: bool,

        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,
    },
    /// Restore account from secure backup.
    Restore {
        /// Input zip archive.
        #[clap(short, long)]
        input: PathBuf,
    },
    /// Rename an account.
    Rename {
        /// Name for the account.
        #[clap(short, long)]
        name: String,

        /// Account name or address.
        #[clap(short, long)]
        account: Option<AccountRef>,
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
    let is_shell = USER.get().is_some();
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
        Command::Backup {
            account,
            output,
            force,
        } => {
            account_backup(account, output, force).await?;
            tracing::info!(target: TARGET, "backup archive created ✓");
        }
        Command::Restore { input } => {
            if let Some(account) = account_restore(input).await? {
                tracing::info!(
                    target: TARGET,
                    "restored {} ({}) ✓",
                    account.label(),
                    account.address()
                );
            }
        }
        Command::Rename { name, account } => {
            account_rename(account, name).await?;
            tracing::info!(target: TARGET, "account renamed ✓");
        }
        Command::Migrate { account, cmd } => {
            let user = resolve_user(account.as_ref(), false).await?;
            match cmd {
                MigrateCommand::Export { output, force } => {
                    let exported =
                        migrate_export(user, output, force).await?;
                    if exported {
                        tracing::info!(target: TARGET, "account exported ✓");
                    }
                }
                MigrateCommand::Import {
                    input,
                    format,
                    name,
                } => {
                    migrate_import(user, input, format, name).await?;
                    tracing::info!(target: TARGET, "file imported ✓");
                }
            }
        }
        Command::Contacts { account, cmd } => {
            let user = resolve_user(account.as_ref(), false).await?;

            // Get the current folder so that the shell client
            // does not lose context when importing and exporting contacts
            let original_folder = {
                let mut owner = user.write().await;

                let current = {
                    let storage = owner.storage().await?;
                    let reader = storage.read().await;
                    reader.current_folder()
                };

                let contacts = owner
                    .contacts_folder()
                    .await
                    .ok_or_else(|| Error::NoContactsFolder)?;
                owner.open_folder(&contacts).await?;
                current
            };

            match cmd {
                ContactsCommand::Export { output, force } => {
                    contacts_export(Arc::clone(&user), output, force).await?;
                    tracing::info!(target: TARGET, "contacts exported ✓");
                    if let Some(folder) = original_folder {
                        let mut owner = user.write().await;
                        owner.open_folder(&folder).await?;
                    }
                }
                ContactsCommand::Import { input } => {
                    contacts_import(Arc::clone(&user), input).await?;
                    tracing::info!(target: TARGET, "contacts imported ✓");
                    if let Some(folder) = original_folder {
                        let mut owner = user.write().await;
                        owner.open_folder(&folder).await?;
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
                tracing::info!(target: TARGET, "account deleted ✓");
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
    let data = owner.account_data().await?;

    if json {
        serde_json::to_writer_pretty(&mut std::io::stdout(), &data)?;
    } else {
        println!("{} {}", data.account.address(), data.account.label());
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

/// Create a backup zip archive.
async fn account_backup(
    account: Option<AccountRef>,
    output: PathBuf,
    force: bool,
) -> Result<()> {
    let account = resolve_account(account.as_ref())
        .await
        .ok_or_else(|| Error::NoAccountFound)?;

    if !force && vfs::try_exists(&output).await? {
        return Err(Error::FileExists(output));
    }

    let account = find_account(&account)
        .await?
        .ok_or(Error::NoAccount(account.to_string()))?;
    let address = account.address();
    let paths = Paths::new(Paths::data_dir()?, &address.to_string());

    AccountBackup::export_archive_file(&output, address, &paths).await?;
    Ok(())
}

/// Restore from a zip archive.
async fn account_restore(input: PathBuf) -> Result<Option<PublicIdentity>> {
    if !vfs::try_exists(&input).await?
        || !vfs::metadata(&input).await?.is_file()
    {
        return Err(Error::NotFile(input));
    }

    let reader = vfs::File::open(&input).await?;
    let inventory: Inventory =
        AccountBackup::restore_archive_inventory(reader).await?;
    let account_ref = AccountRef::Address(inventory.manifest.address);
    let account = find_account(&account_ref).await?;

    let mut owner = if let Some(account) = account {
        let confirmed = read_flag(Some(
            "Overwrite all account data from backup? (y/n) ",
        ))?;
        if !confirmed {
            return Ok(None);
        }

        let account = AccountRef::Name(account.label().to_owned());
        let (owner, password) = sign_in(&account).await?;
        Some((owner, password))
    } else {
        None
    };

    let account = if let Some((mut owner, password)) = owner.take() {
        let files_dir = owner.paths().files_dir();
        let options = RestoreOptions {
            selected: inventory.vaults,
            files_dir: Some(ExtractFilesLocation::Path(files_dir.to_owned())),
        };
        owner
            .restore_backup_archive(&input, password, options, None)
            .await?
    } else {
        let address = inventory.manifest.address.to_string();
        let paths = Paths::new(Paths::data_dir()?, &address);
        let files_dir = paths.files_dir();
        let options = RestoreOptions {
            selected: inventory.vaults,
            files_dir: Some(ExtractFilesLocation::Path(files_dir.to_owned())),
        };
        NetworkAccount::import_backup_archive(&input, options, None).await?
    };

    Ok(Some(account))
}

/// Rename an account.
async fn account_rename(
    account: Option<AccountRef>,
    name: String,
) -> Result<()> {
    let user = resolve_user(account.as_ref(), false).await?;
    let mut owner = user.write().await;
    owner.rename_account(name).await?;
    Ok(())
}

/// Delete an account.
async fn account_delete(account: Option<AccountRef>) -> Result<bool> {
    let is_shell = USER.get().is_some();

    let account = if !is_shell {
        // For deletion we don't accept account inference, it must
        // be specified explicitly
        account.as_ref().ok_or_else(|| Error::ExplicitAccount)?;

        resolve_account(account.as_ref())
            .await
            .ok_or_else(|| Error::NoAccountFound)?
    } else {
        // Shell users can only delete their own account
        if account.is_some() {
            return Err(Error::NotShellAccount);
        }

        let user = USER.get().unwrap();

        // Verify the password for shell users
        // before deletion
        verify(Arc::clone(&user)).await?;

        let owner = user.read().await;
        owner.account_ref().await?
    };

    let user = resolve_user(Some(&account), false).await?;
    let mut owner = user.write().await;

    let prompt = format!(
        r#"Delete account "{}" (y/n)? "#,
        owner.account_label().await?,
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
    let prompt = format!(
        r#"Export UNENCRYPTED account "{}" (y/n)? "#,
        owner.account_label().await?,
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
    let mut owner = user.write().await;
    owner.export_all_contacts(output).await?;
    Ok(())
}

/// Import contacts from a vCard.
async fn contacts_import(user: Owner, input: PathBuf) -> Result<()> {
    let mut owner = user.write().await;
    let content = vfs::read_to_string(&input).await?;
    owner.import_contacts(&content, |_| {}).await?;
    Ok(())
}
