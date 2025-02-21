//! Import filesystem backed accounts into a database.
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sos_backend::BackendTarget;
use sos_client_storage::ClientStorage;
use sos_core::{constants::JSON_EXT, Paths, PublicIdentity};
use sos_database::{
    async_sqlite::JournalMode, migrations::migrate_client,
    open_file_with_journal_mode, open_memory,
};
use sos_external_files::list_external_files;
use sos_filesystem::archive::AccountBackup;
use sos_server_storage::ServerStorage;
use sos_sync::SyncStatus;
use sos_vault::list_accounts;
use sos_vfs::{self as vfs, File};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

mod db_import;

use db_import::AccountStorage;

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
) -> Result<(Vec<PublicIdentity>, Vec<(SyncStatus, SyncStatus)>)> {
    let mut client = if !options.dry_run {
        let db_file = options
            .db_file
            .as_ref()
            .unwrap_or(options.paths.database_file());

        let mut client =
            open_file_with_journal_mode(db_file, JournalMode::Memory).await?;
        let report = migrate_client(&mut client).await?;
        for migration in report.applied_migrations() {
            tracing::debug!(
                name = %migration.name(),
                version = %migration.version(),
                "import_accounts::migration",);
        }
        client
    } else {
        open_memory().await?
    };

    db_import::import_globals(&mut client, &options.paths).await?;

    let accounts = list_accounts(Some(&options.paths)).await?;
    let mut sync_status = Vec::new();
    for account in &accounts {
        let account_paths =
            options.paths.with_account_id(account.account_id());

        let fs_storage = if options.paths.is_server() {
            AccountStorage::Server(
                ServerStorage::new(
                    account.account_id(),
                    BackendTarget::FileSystem(account_paths.clone()),
                )
                .await?,
            )
        } else {
            AccountStorage::Client(
                ClientStorage::new_unauthenticated(
                    account.account_id(),
                    BackendTarget::FileSystem(account_paths.clone()),
                )
                .await?,
            )
        };

        // Compute account status so we can compare and assert
        // after importing the account
        let fs_status = fs_storage.sync_status().await?;

        let db_storage = db_import::import_account(
            fs_storage,
            &mut client,
            &account_paths,
            &account,
        )
        .await?;

        // Compute the imported account status
        let db_status = db_storage.sync_status().await?;

        sync_status.push((fs_status, db_status));
    }

    Ok((accounts, sync_status))
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

    let db_temp = NamedTempFile::new_in(data_dir.as_ref())?;
    options.db_file = Some(db_temp.path().to_owned());

    tracing::debug!("upgrade_accounts::import_accounts");

    let (accounts, sync_status) = import_accounts(&options).await?;
    let accounts_status = accounts.iter().zip(sync_status.iter()).collect();
    assert_sync_status(&options, accounts_status).await?;

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
        tracing::debug!(
          temp = %db_temp.path().display(),
          dest = %options.paths.database_file().display(),
          "upgrade_accounts::move_db_into_place");

        // Move the temp file into place
        vfs::rename(db_temp.path(), options.paths.database_file()).await?;
    }

    Ok(result)
}

#[derive(Serialize, Deserialize)]
struct UpgradeErrorReport {
    account: PublicIdentity,
    filesystem: SyncStatus,
    database: SyncStatus,
}

async fn assert_sync_status(
    options: &UpgradeOptions,
    accounts_status: Vec<(&PublicIdentity, &(SyncStatus, SyncStatus))>,
) -> Result<()> {
    for (account, (fs_status, db_status)) in accounts_status {
        /*
        println!(
            "{} <-> {} ({})",
            fs_status.root,
            db_status.root,
            fs_status.root == db_status.root
        );
        */

        tracing::info!(
            account_id = %account.account_id(),
            fs = %fs_status.root,
            db = %db_status.root,
            "upgrade::ok"
        );

        if fs_status.root != db_status.root {
            tracing::error!(
                account_id = %account.account_id(),
                fs = %fs_status.root,
                db = %db_status.root,
                "upgrade::status_error"
            );

            if fs_status.identity != db_status.identity {
                tracing::error!(
                    fs = ?fs_status.identity,
                    db = ?db_status.identity,
                    "upgrade::status_error::identity"
                );
            }

            if fs_status.account != db_status.account {
                tracing::error!(
                    fs = ?fs_status.account,
                    db = ?db_status.account,
                    "upgrade::status_error::account"
                );
            }

            if fs_status.device != db_status.device {
                tracing::error!(
                    fs = ?fs_status.device,
                    db = ?db_status.device,
                    "upgrade::status_error::device"
                );
            }

            if fs_status.files != db_status.files {
                tracing::error!(
                    fs = ?fs_status.files,
                    db = ?db_status.files,
                    "upgrade::status_error::files"
                );
            }

            if fs_status.folders != db_status.folders {
                tracing::error!(
                    fs = ?fs_status.folders,
                    db = ?db_status.folders,
                    "upgrade::status_error::folders"
                );
            }

            // Write out to an error log with more info
            let logs_dir = options.paths.logs_dir();
            if !vfs::try_exists(&logs_dir).await? {
                vfs::create_dir_all(&logs_dir).await?;
            }
            let mut upgrade_log_file = logs_dir.join("db_upgrade_error");
            upgrade_log_file.set_extension(JSON_EXT);

            let error_report = UpgradeErrorReport {
                account: account.clone(),
                filesystem: fs_status.clone(),
                database: db_status.clone(),
            };
            let log_data = serde_json::to_vec_pretty(&error_report)?;
            vfs::write(&upgrade_log_file, &log_data).await?;

            // Abort the upgrade
            return Err(Error::AccountStatus(
                *account.account_id(),
                fs_status.root,
                db_status.root,
                upgrade_log_file,
            ));
        }
    }

    Ok(())
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
