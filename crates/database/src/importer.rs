//! Import filesystem backed accounts into a database.
use crate::{db, migrations::migrate_client, Error, Result};
use sos_core::{Paths, PublicIdentity};
use sos_vault::list_accounts;
use sos_vfs as vfs;
use std::path::{Path, PathBuf};

/// Options for upgrading to SQLite backend.
#[derive(Debug)]
pub struct UpgradeOptions {
    /// Perform a dry run.
    pub dry_run: bool,
    /// Accounts are server-side storage.
    pub server: bool,
    /// Keep the old files on disc.
    pub keep_stale_files: bool,
    /// Move file blobs.
    pub move_file_blobs: bool,
}

impl Default for UpgradeOptions {
    fn default() -> Self {
        Self {
            dry_run: true,
            server: false,
            keep_stale_files: false,
            move_file_blobs: true,
        }
    }
}

/// Result of upgrading to SQLite backend.
#[derive(Debug, Default)]
pub struct UpgradeResult {
    /// Database file location.
    pub database_file: PathBuf,
    /// List of migrated accounts.
    pub accounts: Vec<PublicIdentity>,
    /// List of moved file blobs.
    pub moved_blobs: Vec<PathBuf>,
    /// List of deleted files.
    pub deleted_files: Vec<PathBuf>,
}

/// Import all accounts found on disc.
pub async fn import_accounts(
    data_dir: impl AsRef<Path>,
    options: &UpgradeOptions,
) -> Result<Vec<PublicIdentity>> {
    let paths = if options.server {
        Paths::new_global_server(data_dir.as_ref())
    } else {
        Paths::new_global(data_dir.as_ref())
    };

    let db_file = paths.database_file();
    if db_file.exists() && !options.dry_run {
        return Err(Error::DatabaseExists(db_file.to_owned()));
    }

    let mut client = if !options.dry_run {
        let mut client = db::open_file(paths.database_file()).await?;
        migrate_client(&mut client).await?;
        client
    } else {
        db::open_memory().await?
    };

    db::import_globals(&mut client, &paths).await?;

    let accounts = list_accounts(Some(&paths)).await?;
    for account in &accounts {
        let account_paths = if options.server {
            Paths::new_server(
                paths.documents_dir(),
                account.account_id().to_string(),
            )
        } else {
            Paths::new(
                paths.documents_dir(),
                account.account_id().to_string(),
            )
        };

        db::import_account(
            &mut client,
            &account_paths,
            &account,
            options.server,
        )
        .await?;
    }
    Ok(accounts)
}

/// Upgrade all accounts found on disc.
pub async fn upgrade_accounts(
    data_dir: impl AsRef<Path>,
    options: UpgradeOptions,
) -> Result<UpgradeResult> {
    let paths = if options.server {
        Paths::new_global_server(data_dir.as_ref())
    } else {
        Paths::new_global(data_dir.as_ref())
    };

    let mut result = UpgradeResult::default();
    let accounts = import_accounts(data_dir, &options).await?;

    if options.move_file_blobs {
        move_file_blobs(&paths, accounts.as_slice(), &options).await?;
    }

    if !options.keep_stale_files {
        result.deleted_files =
            delete_stale_files(&paths, accounts.as_slice(), &options).await?;
    }

    result.accounts = accounts;
    result.database_file = paths.database_file().to_owned();

    Ok(result)
}

async fn move_file_blobs(
    paths: &Paths,
    accounts: &[PublicIdentity],
    options: &UpgradeOptions,
) -> Result<()> {
    todo!("move file blobs");
    // Ok(())
}

async fn delete_stale_files(
    paths: &Paths,
    accounts: &[PublicIdentity],
    options: &UpgradeOptions,
) -> Result<Vec<PathBuf>> {
    let mut files = vec![
        paths.identity_dir().to_owned(),
        paths.audit_file().to_owned(),
    ];

    for account in accounts {
        let account_path =
            paths.local_dir().join(account.account_id().to_string());
        files.push(account_path);
    }

    if !options.dry_run {
        for file in &files {
            if file.is_dir() {
                vfs::remove_dir_all(file).await?;
            } else {
                vfs::remove_file(file).await?;
            }
        }
    }

    Ok(files)
}
