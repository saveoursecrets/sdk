//! Import filesystem backed accounts into a database.
use crate::{db, migrations::migrate_client, Error, Result};
use sos_core::{Paths, PublicIdentity};
use sos_vault::list_accounts;
use sos_vfs as vfs;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

/// Options for upgrading to SQLite backend.
#[derive(Debug)]
pub struct UpgradeOptions {
    /// Perform a dry run.
    pub dry_run: bool,
    /// Database file to write to.
    ///
    /// When dry run is enabled this is ignored; if no
    /// path is specified and dry run is not enabled this
    /// will write to the expected location for a database file.
    pub db_file: Option<PathBuf>,
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
            db_file: None,
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
async fn import_accounts(
    paths: &Paths,
    options: &UpgradeOptions,
) -> Result<Vec<PublicIdentity>> {
    let mut client = if !options.dry_run {
        let db_file =
            options.db_file.as_ref().unwrap_or(paths.database_file());
        let mut client = db::open_file(db_file).await?;
        migrate_client(&mut client).await?;
        client
    } else {
        db::open_memory().await?
    };

    db::import_globals(&mut client, paths).await?;

    let accounts = list_accounts(Some(paths)).await?;
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
    mut options: UpgradeOptions,
) -> Result<UpgradeResult> {
    let paths = if options.server {
        Paths::new_global_server(data_dir.as_ref())
    } else {
        Paths::new_global(data_dir.as_ref())
    };

    //paths.ensure().await?;

    let db_file = paths.database_file();
    if db_file.exists() && !options.dry_run {
        return Err(Error::DatabaseExists(db_file.to_owned()));
    }

    let db_temp = NamedTempFile::new()?;
    options.db_file = Some(db_temp.path().to_owned());

    let mut result = UpgradeResult::default();
    let accounts = import_accounts(&paths, &options).await?;

    if options.move_file_blobs {
        move_file_blobs(&paths, accounts.as_slice(), &options).await?;
    }

    if !options.keep_stale_files {
        result.deleted_files =
            delete_stale_files(&paths, accounts.as_slice(), &options).await?;
    }

    result.accounts = accounts;
    result.database_file = paths.database_file().to_owned();

    // Move the temp file into place
    #[cfg(not(target_os = "linux"))]
    vfs::rename(db_temp.path(), paths.database_file()).await?;

    // On Linux we have to copy to avoid cross-device link error
    #[cfg(target_os = "linux")]
    {
        let mut source = tokio::fs::File::open(db_temp.path()).await?;
        let mut dest = tokio::fs::File::create(paths.database_file()).await?;
        tokio::io::copy(&mut source, &mut dest).await?;
    }

    Ok(result)
}

async fn move_file_blobs(
    paths: &Paths,
    accounts: &[PublicIdentity],
    options: &UpgradeOptions,
) -> Result<()> {
    // todo!("move file blobs");
    Ok(())
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
