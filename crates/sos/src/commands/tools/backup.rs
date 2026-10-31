use crate::{
    Error, Result,
    helpers::account::{find_account, resolve_account},
};
use clap::Subcommand;
use sos_backend::{
    BackendTarget,
    archive::{list_backup_archive_accounts, read_backup_archive_manifest},
};
use sos_cli_helpers::messages::success;
use sos_core::{AccountId, AccountRef, Paths, PublicIdentity};
use sos_vfs as vfs;
use std::path::PathBuf;

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Export to a backup archive.
    Export {
        /// Force overwrite an existing file.
        #[clap(short, long)]
        force: bool,

        /// Specific account to export.
        #[clap(short, long)]
        account: Option<AccountRef>,

        /// Output backup archive ZIP file.
        output: PathBuf,
    },
    /// Import from a backup archive.
    Import {
        /// Input backup archive ZIP file.
        input: PathBuf,
    },
    /// Print the manifest in a backup archive.
    Manifest {
        /// Input backup archive ZIP file.
        input: PathBuf,
    },
    /// List accounts in a backup archive.
    #[clap(alias = "ls")]
    ListAccounts {
        /// Input backup archive ZIP file.
        input: PathBuf,
    },
    /// Print the version of a backup archive.
    Version {
        /// Input backup archive ZIP file.
        input: PathBuf,
    },
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Export {
            output,
            force,
            account,
        } => {
            export_account_backup_archive(account, output, force).await?;
            success("Backup archive created");
        }
        Command::Import { input } => {
            let accounts = self::import_account_backup_archive(input).await?;
            for account in accounts {
                success(format!("Account restored {}", account.label()));
            }
        }
        Command::Manifest { input } => {
            let manifest = read_backup_archive_manifest(&input).await?;
            serde_json::to_writer_pretty(std::io::stdout(), &manifest)?;
        }
        Command::ListAccounts { input } => {
            let accounts = list_backup_archive_accounts(&input).await?;
            for account in &accounts {
                println!("{} {}", account.account_id(), account.label());
            }
        }
        Command::Version { input } => {
            let manifest = read_backup_archive_manifest(&input).await?;
            println!("Version {}", manifest.version() as u8);
        }
    }
    Ok(())
}

/// Create a backup zip archive.
async fn export_account_backup_archive(
    account: Option<AccountRef>,
    output: PathBuf,
    force: bool,
) -> Result<()> {
    let exists = vfs::try_exists(&output).await?;
    if exists {
        if !force {
            return Err(Error::FileExists(output));
        } else {
            vfs::remove_file(&output).await?;
        }
    }

    let paths = Paths::new_client(Paths::data_dir()?);
    let target = BackendTarget::from_paths(&paths).await?;

    // Database backups exports all accounts by default
    let account_id = if paths.is_using_db() {
        // But the API requires an account identifier for backwards compat
        AccountId::random()
    // Legacy file system requires an account identifier
    } else {
        let account = resolve_account(account.as_ref())
            .await?
            .ok_or_else(|| Error::NoAccountFound)?;

        let account = find_account(&account)
            .await?
            .ok_or(Error::NoAccount(account.to_string()))?;
        *account.account_id()
    };

    sos_backend::archive::export_backup_archive(output, &target, &account_id)
        .await?;

    Ok(())
}

/// Import from a zip archive.
async fn import_account_backup_archive(
    input: PathBuf,
) -> Result<Vec<PublicIdentity>> {
    if !vfs::try_exists(&input).await?
        || !vfs::metadata(&input).await?.is_file()
    {
        return Err(Error::NotFile(input));
    }

    let paths = Paths::new_client(Paths::data_dir()?);
    let target = BackendTarget::from_paths(&paths).await?;
    let accounts =
        sos_backend::archive::import_backup_archive(&input, &target).await?;
    Ok(accounts)
}
