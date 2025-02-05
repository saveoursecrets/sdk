//! Import filesystem backed accounts into a database.
use crate::{db, migrations::migrate_client, Error, Result};
use serde::{Deserialize, Serialize};
use sos_core::{Paths, PublicIdentity};
use sos_external_files::list_external_files;
use sos_vault::list_accounts;
use sos_vfs::{self as vfs, File};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

use sos_filesystem::archive::AccountBackup;

mod db_import;

/// Options for upgrading to SQLite backend.
#[derive(Debug)]
pub struct UpgradeOptions {
    /// Storage paths.
    pub paths: Paths,
    /// Perform a dry run.
    pub dry_run: bool,
    /// Database file to write to.
    ///
    /// When dry run is enabled this is ignored; if no
    /// path is specified and dry run is not enabled this
    /// will write to the expected location for a database file.
    pub db_file: Option<PathBuf>,
    /// Backup accounts to this directory before upgrade.
    ///
    /// If the destination does not exist the upgrade will
    /// attempt to create the directory.
    pub backup_directory: Option<PathBuf>,
    /// Keep the old files on disc.
    pub keep_stale_files: bool,
    /// Move file blobs.
    pub copy_file_blobs: bool,
}

impl Default for UpgradeOptions {
    fn default() -> Self {
        Self {
            paths: Default::default(),
            dry_run: true,
            db_file: None,
            backup_directory: None,
            keep_stale_files: false,
            copy_file_blobs: true,
        }
    }
}

/// Result of upgrading to SQLite backend.
#[derive(Debug, Serialize, Deserialize)]
pub struct UpgradeResult {
    /// Global paths for the upgrade.
    pub global_paths: Paths,
    /// Database file location.
    pub database_file: PathBuf,
    /// Account backup locations.
    pub backups: Vec<PathBuf>,
    /// List of migrated accounts.
    pub accounts: Vec<PublicIdentity>,
    /// List of copied file blobs.
    pub copied_blobs: Vec<(PathBuf, PathBuf)>,
    /// List of deleted files.
    pub deleted_files: Vec<PathBuf>,
}

impl UpgradeResult {
    fn new(paths: Paths) -> Self {
        Self {
            database_file: paths.database_file().to_owned(),
            global_paths: paths,
            backups: Vec::new(),
            accounts: Vec::new(),
            copied_blobs: Vec::new(),
            deleted_files: Vec::new(),
        }
    }
}

/// Import all accounts found on disc.
async fn import_accounts(
    options: &UpgradeOptions,
) -> Result<Vec<PublicIdentity>> {
    let mut client = if !options.dry_run {
        let db_file = options
            .db_file
            .as_ref()
            .unwrap_or(options.paths.database_file());
        let mut client = db::open_file(db_file).await?;
        migrate_client(&mut client).await?;
        client
    } else {
        db::open_memory().await?
    };

    db_import::import_globals(&mut client, &options.paths).await?;

    let accounts = list_accounts(Some(&options.paths)).await?;
    for account in &accounts {
        let account_paths =
            options.paths.with_account_id(account.account_id());

        db_import::import_account(&mut client, &account_paths, &account)
            .await?;
    }
    Ok(accounts)
}

/// Upgrade all accounts found on disc.
pub async fn upgrade_accounts(
    data_dir: impl AsRef<Path>,
    mut options: UpgradeOptions,
) -> Result<UpgradeResult> {
    tracing::debug!(
      path = ?data_dir.as_ref(),
      options = ?options,
      "upgrade_accounts");

    options.paths.ensure_db().await?;

    let db_file = options.paths.database_file();
    if db_file.exists() && !options.dry_run {
        return Err(Error::DatabaseExists(db_file.to_owned()));
    }

    let mut result = UpgradeResult::new(options.paths.clone());

    if !options.dry_run && options.backup_directory.is_some() {
        tracing::debug!("upgrade_accounts::create_backups");
        result.backups = create_backups(&options).await?;
    }

    let db_temp = NamedTempFile::new()?;
    options.db_file = Some(db_temp.path().to_owned());

    tracing::debug!("upgrade_accounts::import_accounts");

    let accounts = import_accounts(&options).await?;

    if options.copy_file_blobs {
        tracing::debug!("upgrade_accounts::copy_file_blobs");

        result.copied_blobs =
            copy_file_blobs(accounts.as_slice(), &options).await?;
    }

    if !options.keep_stale_files {
        tracing::debug!("upgrade_accounts::delete_stale_files");

        result.deleted_files =
            delete_stale_files(accounts.as_slice(), &options).await?;
    }

    result.accounts = accounts;
    result.database_file = options.paths.database_file().to_owned();

    if !options.dry_run {
        tracing::debug!("upgrade_accounts::move_db_into_place");

        // Move the temp file into place
        #[cfg(not(target_os = "linux"))]
        vfs::rename(db_temp.path(), options.paths.database_file()).await?;

        // On Linux we have to copy to avoid cross-device link error
        #[cfg(target_os = "linux")]
        {
            let mut source = File::open(db_temp.path()).await?;
            let mut dest = File::create(paths.database_file()).await?;
            tokio::io::copy(&mut source, &mut dest).await?;
        }
    }

    Ok(result)
}

async fn create_backups(options: &UpgradeOptions) -> Result<Vec<PathBuf>> {
    let backup_directory = options.backup_directory.as_ref().unwrap();
    if !vfs::try_exists(&backup_directory).await? {
        vfs::create_dir_all(&backup_directory).await?;
    }

    let mut backup_files = Vec::new();
    let accounts = list_accounts(Some(&options.paths)).await?;
    for account in accounts {
        let account_paths =
            options.paths.with_account_id(account.account_id());

        let mut backup_path =
            backup_directory.join(account.account_id().to_string());
        backup_path.set_extension("zip");

        AccountBackup::export_archive_file(
            &backup_path,
            account.account_id(),
            &account_paths,
        )
        .await?;

        backup_files.push(backup_path);
    }

    Ok(backup_files)
}

async fn copy_file_blobs(
    accounts: &[PublicIdentity],
    options: &UpgradeOptions,
) -> Result<Vec<(PathBuf, PathBuf)>> {
    let mut copied = Vec::new();

    for account in accounts {
        let account_paths =
            options.paths.with_account_id(account.account_id());

        let source_external_files =
            list_external_files(&account_paths).await?;

        for file in source_external_files {
            let source = account_paths.file_location(
                file.vault_id(),
                file.secret_id(),
                file.file_name().to_string(),
            );

            let dest = account_paths.blob_location(
                file.vault_id(),
                file.secret_id(),
                file.file_name().to_string(),
            );

            if !options.dry_run {
                tracing::debug!(
                  source = ?source,
                  dest = ?dest,
                  "upgrade_accounts::copy_file");

                if let Some(parent) = dest.parent() {
                    if !vfs::try_exists(parent).await? {
                        vfs::create_dir_all(parent).await?;
                    }
                }

                let mut input = File::open(&source).await?;
                let mut output = File::create(&dest).await?;
                tokio::io::copy(&mut input, &mut output).await?;
            }

            copied.push((source, dest));
        }
    }

    Ok(copied)
}

async fn delete_stale_files(
    accounts: &[PublicIdentity],
    options: &UpgradeOptions,
) -> Result<Vec<PathBuf>> {
    let mut files = vec![
        options.paths.identity_dir().to_owned(),
        options.paths.audit_file().to_owned(),
    ];

    for account in accounts {
        let account_path = options
            .paths
            .local_dir()
            .join(account.account_id().to_string());
        files.push(account_path);
    }

    if !options.dry_run {
        for file in &files {
            tracing::debug!(
              file = ?file,
              "upgrade_accounts::delete_file");

            if file.is_dir() {
                vfs::remove_dir_all(file).await?;
            } else {
                vfs::remove_file(file).await?;
            }
        }
    }

    Ok(files)
}
