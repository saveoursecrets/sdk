use clap::Subcommand;
use std::path::PathBuf;

use sos_core::{
    account::{
        archive::Inventory, AccountBackup, AccountInfo, AccountRef,
        ExtractFilesLocation, LocalAccounts, RestoreOptions,
    },
    storage::StorageDirs,
};
use sos_node::client::provider::ProviderFactory;

use crate::{
    helpers::{
        account::{
            find_account, list_accounts, new_account, resolve_account,
            resolve_user, sign_in, Owner, USER,
        },
        readline::read_flag,
    },
    Error, Result,
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

        /// Include system folders.
        #[clap(short, long)]
        system: bool,

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
    /// Delete an account.
    Delete {
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
            system,
        } => {
            account_info(account, verbose, system).await?;
        }
        Command::Backup {
            account,
            output,
            force,
        } => {
            account_backup(account, output, force).await?;
        }
        Command::Restore { input } => {
            if let Some(account) = account_restore(input).await? {
                println!("{} ({}) ✓", account.label(), account.address());
            }
        }
        Command::Rename { name, account } => {
            account_rename(account, name, factory).await?;
            println!("account renamed ✓");
        }
        Command::Delete { account } => {
            let deleted = account_delete(account, factory).await?;
            if deleted {
                println!("account deleted ✓");
                if is_shell {
                    std::process::exit(0);
                }
            }
        }
        Command::Migrate { account, cmd } => {
            let user = resolve_user(account, factory, false).await?;
            match cmd {
                MigrateCommand::Export { output, force } => {
                    let exported = migrate_export(user, output, force).await?;
                    if exported {
                        println!("account exported ✓");
                    }
                }
                MigrateCommand::Import { input: _ } => {}
            }
        }
    }

    Ok(())
}

/// Print account info.
pub async fn account_info(
    account: Option<AccountRef>,
    verbose: bool,
    system: bool,
) -> Result<()> {
    let account = resolve_account(account)
        .await
        .ok_or_else(|| Error::NoAccountFound)?;

    let (owner, _) = sign_in(&account, ProviderFactory::Local).await?;
    let folders = LocalAccounts::list_local_vaults(
        owner.user.identity().address(),
        system,
    )?;

    println!(
        "{} {}",
        owner.user.account().address(),
        owner.user.account().label()
    );
    for (summary, _) in folders {
        if verbose {
            println!("{} {}", summary.id(), summary.name());
        } else {
            println!("{}", summary.name());
        }
    }
    Ok(())
}

/// Create a backup zip archive.
pub async fn account_backup(
    account: Option<AccountRef>,
    output: PathBuf,
    force: bool,
) -> Result<()> {
    let account = resolve_account(account)
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
pub async fn account_restore(input: PathBuf) -> Result<Option<AccountInfo>> {
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
pub async fn account_rename(
    account: Option<AccountRef>,
    name: String,
    factory: ProviderFactory,
) -> Result<()> {
    let account = resolve_account(account)
        .await
        .ok_or_else(|| Error::NoAccountFound)?;

    let (mut owner, _) = sign_in(&account, factory).await?;
    owner.user.rename_account(name)?;
    Ok(())
}

/// Delete an account.
pub async fn account_delete(
    account: Option<AccountRef>,
    factory: ProviderFactory,
) -> Result<bool> {
    let is_shell = USER.get().is_some();

    let account = if !is_shell {
        // For deletion we don't accept account inference, it must
        // be specified explicitly
        account.as_ref().ok_or_else(|| Error::ExplicitAccount)?;

        resolve_account(account)
            .await
            .ok_or_else(|| Error::NoAccountFound)?
    } else {
        // Shell users can only delete their own account
        if account.is_some() {
            return Err(Error::NotShellAccount);
        }

        let user = USER.get().unwrap();
        let owner = user.read().await;
        owner.user.account().into()
    };

    let (mut owner, _) = sign_in(&account, factory).await?;

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
pub async fn migrate_export(
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
