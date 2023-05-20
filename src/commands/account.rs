use clap::Subcommand;
use std::{path::PathBuf, sync::Arc};

use sos_net::{
    client::provider::ProviderFactory,
    migrate::import::{ImportFormat, ImportTarget},
};
use sos_sdk::{
    account::{
        archive::Inventory, AccountBackup, AccountInfo, AccountRef,
        ExtractFilesLocation, RestoreOptions,
    },
    storage::StorageDirs,
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

pub async fn run(cmd: Command, factory: ProviderFactory) -> Result<()> {
    let is_shell = USER.get().is_some();
    match cmd {
        Command::New { name, folder_name } => {
            new_account(name, folder_name).await?;
        }
        Command::List { verbose } => {
            list_accounts(verbose)?;
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
            account_rename(account, name, factory).await?;
            println!("account renamed ✓");
        }
        Command::Migrate { account, cmd } => {
            let user = resolve_user(account.as_ref(), factory, false).await?;
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
            let user = resolve_user(account.as_ref(), factory, false).await?;

            {
                let mut owner = user.write().await;
                let contacts = owner
                    .contacts_folder()
                    .ok_or_else(|| Error::NoContactsFolder)?;
                owner.open_folder(&contacts)?;
            }

            match cmd {
                ContactsCommand::Export { output, force } => {
                    contacts_export(user, output, force).await?;
                    tracing::info!(target: TARGET, "contacts exported ✓");
                }
                ContactsCommand::Import { input } => {
                    contacts_import(user, input).await?;
                    tracing::info!(target: TARGET, "contacts imported ✓");
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
            let user = resolve_user(account.as_ref(), factory, true).await?;
            let owner = user.read().await;
            let statistics = owner.statistics();

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
            let deleted = account_delete(account, factory).await?;
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
    let user =
        resolve_user(account.as_ref(), ProviderFactory::Local, false).await?;
    let owner = user.read().await;
    let data = owner.account_data()?;

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

    if !force && output.exists() {
        return Err(Error::FileExists(output));
    }

    let account = find_account(&account)?
        .ok_or(Error::NoAccount(account.to_string()))?;
    AccountBackup::export_archive_file(&output, account.address())?;
    Ok(())
}

/// Restore from a zip archive.
async fn account_restore(input: PathBuf) -> Result<Option<AccountInfo>> {
    if !input.exists() || !input.is_file() {
        return Err(Error::NotFile(input));
    }

    let reader = std::fs::File::open(&input)?;
    let inventory: Inventory =
        AccountBackup::restore_archive_inventory(reader)?;
    let account_ref = AccountRef::Address(inventory.manifest.address);
    let account = find_account(&account_ref)?;

    let (provider, passphrase) = if let Some(account) = account {
        let confirmed = read_flag(Some(
            "Overwrite all account data from backup? (y/n) ",
        ))?;
        if !confirmed {
            return Ok(None);
        }

        let account = AccountRef::Name(account.label().to_owned());
        let (owner, _) = sign_in(&account, ProviderFactory::Local).await?;
        (Some(owner.storage), None)
    } else {
        (None, None)
    };

    let files_dir =
        StorageDirs::files_dir(inventory.manifest.address.to_string())?;
    let options = RestoreOptions {
        selected: inventory.vaults,
        passphrase,
        files_dir: Some(ExtractFilesLocation::Path(files_dir)),
    };
    let reader = std::fs::File::open(&input)?;

    let (targets, account) = AccountBackup::restore_archive_buffer(
        reader,
        options,
        provider.is_some(),
    )?;

    if let Some(mut provider) = provider {
        provider.restore_archive(&targets).await?;
    }

    Ok(Some(account))
}

/// Rename an account.
async fn account_rename(
    account: Option<AccountRef>,
    name: String,
    factory: ProviderFactory,
) -> Result<()> {
    let user = resolve_user(account.as_ref(), factory, false).await?;
    let mut owner = user.write().await;
    owner.user.rename_account(name)?;
    Ok(())
}

/// Delete an account.
async fn account_delete(
    account: Option<AccountRef>,
    factory: ProviderFactory,
) -> Result<bool> {
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
        owner.user.account().into()
    };

    let user = resolve_user(Some(&account), factory, false).await?;
    let mut owner = user.write().await;

    let prompt = format!(
        r#"Delete account "{}" (y/n)? "#,
        owner.user.account().label(),
    );
    let result = if read_flag(Some(&prompt))? {
        owner.delete_account()?;
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
    if !force && output.exists() {
        return Err(Error::FileExists(output));
    }

    let owner = user.read().await;
    let prompt = format!(
        r#"Export UNENCRYPTED account "{}" (y/n)? "#,
        owner.user.account().label(),
    );

    let result = if read_flag(Some(&prompt))? {
        owner.export_unsafe_archive(output)?;
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
    if !force && output.exists() {
        return Err(Error::FileExists(output));
    }
    let mut owner = user.write().await;
    owner.export_all_vcards(output).await?;
    Ok(())
}

/// Import contacts from a vCard.
async fn contacts_import(user: Owner, input: PathBuf) -> Result<()> {
    let mut owner = user.write().await;
    let content = std::fs::read_to_string(&input)?;
    owner.import_vcard(&content, |_| {}).await?;
    Ok(())
}
