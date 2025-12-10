//! Backend database and file system storage.
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![allow(clippy::large_enum_variant)]

mod access_point;
#[cfg(feature = "archive")]
pub mod archive;
#[cfg(feature = "audit")]
pub mod audit;
pub mod compact;
mod error;
mod event_log;
mod folder;
mod helpers;
#[cfg(feature = "preferences")]
mod preferences;
mod server_origins;
#[cfg(feature = "system-messages")]
mod system_messages;
mod vault_writer;

pub use access_point::BackendAccessPoint as AccessPoint;
pub use error::{Error, StorageError};
pub use event_log::{
    AccountEventLog, BackendEventLog, DeviceEventLog, FolderEventLog,
};
pub use folder::Folder;
pub use helpers::extract_vault;
#[cfg(feature = "preferences")]
pub use preferences::BackendPreferences as Preferences;
pub use server_origins::ServerOrigins;
pub use sos_database as database;
#[cfg(feature = "system-messages")]
pub use system_messages::SystemMessages;
pub use vault_writer::VaultWriter;

#[cfg(feature = "files")]
pub use event_log::FileEventLog;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;

use sos_core::{AccountId, Paths, PublicIdentity, decode};
use sos_database::{
    async_sqlite::Client,
    entity::{
        AccountEntity, AccountRecord, FolderEntity, FolderRecord,
        SecretRecord,
    },
    open_file,
};
use sos_vault::{Summary, Vault};
use sos_vfs as vfs;
use std::{fmt, sync::Arc};

#[cfg(feature = "files")]
use {indexmap::IndexSet, sos_core::ExternalFile};

/// Options for backend target inference.
pub struct InferOptions {
    /// Select the database backend when no accounts.
    pub use_database_when_accounts_empty: bool,
    /// Apply database migrations.
    pub apply_migrations: bool,
    /// Select the backend target audit provider.
    #[cfg(feature = "audit")]
    pub select_audit_provider: bool,
}

impl Default for InferOptions {
    fn default() -> Self {
        Self {
            use_database_when_accounts_empty: true,
            apply_migrations: true,
            #[cfg(feature = "audit")]
            select_audit_provider: true,
        }
    }
}

/// Target backend.
#[derive(Clone)]
pub enum BackendTarget {
    /// File system backend
    FileSystem(Arc<Paths>),
    /// Database backend.
    Database(Arc<Paths>, Client),
}

impl fmt::Display for BackendTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", {
            match self {
                Self::FileSystem(_) => "filesystem",
                Self::Database(_, _) => "database",
            }
        })
    }
}

impl fmt::Debug for BackendTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", {
            match self {
                Self::FileSystem(paths) => format!(
                    "file:{}",
                    paths.documents_dir().to_string_lossy()
                ),
                Self::Database(paths, _) => format!(
                    "sqlite:{}",
                    paths.database_file().to_string_lossy()
                ),
            }
        })
    }
}

impl BackendTarget {
    /// Infer and initialize a new backend target.
    ///
    /// A database backend will be used if a database file already
    /// exists or if there are no accounts. If a database backend
    /// is selected migrations are run otherwise paths are scaffolded
    /// for the file system backend.
    ///
    /// If the `audit` feature is enabled the corresponding audit
    /// provider for the backend is initialized.
    pub async fn infer<T: AsRef<Paths>>(
        paths: T,
        options: InferOptions,
    ) -> Result<Self> {
        let target = BackendTarget::from_paths(paths).await?;

        let mut target = if options.use_database_when_accounts_empty {
            // If there are zero accounts select the database backend
            let accounts = target.list_accounts().await?;
            if accounts.is_empty() {
                let paths = target.paths().clone();
                let client =
                    open_file(paths.as_ref().database_file()).await?;
                BackendTarget::Database(paths, client)
            } else {
                target
            }
        } else {
            target
        };

        match &mut target {
            BackendTarget::FileSystem(paths) => {
                // File system accounts must have
                // the directories scaffolded
                Paths::scaffold(paths.documents_dir()).await?;
            }
            BackendTarget::Database(_, client) => {
                if options.apply_migrations {
                    // Database backend must run migrations
                    crate::database::migrations::migrate_client(client)
                        .await?;
                }
            }
        };

        #[cfg(feature = "audit")]
        if options.select_audit_provider {
            let provider = match &target {
                BackendTarget::FileSystem(paths) => {
                    crate::audit::new_fs_provider(paths.audit_file())
                }
                BackendTarget::Database(_, client) => {
                    crate::audit::new_db_provider(client.clone())
                }
            };
            crate::audit::init_providers(vec![provider]);
        }

        Ok(target)
    }

    /// Trace information about the backend.
    ///
    /// Typically used when an application starts.
    pub async fn dump_info(&self) -> Result<()> {
        tracing::debug!(
            backend_target = %self,
            "backend::dump_info",
        );

        if let Self::Database(_, client) = self {
            let (sqlite_version, compile_options) = client
                .conn_and_then(|conn| {
                    conn.execute("PRAGMA foreign_keys = ON", [])?;
                    let version: String = conn.query_row(
                        "SELECT sqlite_version()",
                        [],
                        |row| row.get(0),
                    )?;

                    let mut stmt = conn.prepare("PRAGMA compile_options")?;
                    let mut compile_options = Vec::new();
                    let rows =
                        stmt.query_map([], |row| row.get::<_, String>(0))?;
                    for option in rows {
                        compile_options.push(option?);
                    }

                    Ok::<_, sos_database::Error>((version, compile_options))
                })
                .await?;
            tracing::debug!(
                version = %sqlite_version,
                compile_options = ?compile_options,
                "backend::dump_info::sqlite",
            );
        }

        Ok(())
    }

    /// Create a backend target from paths.
    pub async fn from_paths<T: AsRef<Paths>>(
        paths: T,
    ) -> Result<BackendTarget> {
        Ok(if paths.as_ref().is_using_db() {
            let client = open_file(paths.as_ref().database_file()).await?;
            BackendTarget::Database(Arc::new(paths.as_ref().clone()), client)
        } else {
            BackendTarget::FileSystem(Arc::new(paths.as_ref().clone()))
        })
    }

    /// Paths for the backend target.
    pub fn paths(&self) -> Arc<Paths> {
        match self {
            Self::FileSystem(paths) => paths.clone(),
            Self::Database(paths, _) => paths.clone(),
        }
    }

    /// Read the device vault.
    pub async fn read_device_vault(
        &self,
        account_id: &AccountId,
    ) -> Result<Option<Vault>> {
        match self {
            BackendTarget::FileSystem(paths) => {
                if vfs::try_exists(paths.device_file()).await? {
                    let buffer = vfs::read(paths.device_file()).await?;
                    let vault: Vault = decode(&buffer).await?;
                    Ok(Some(vault))
                } else {
                    Ok(None)
                }
            }
            BackendTarget::Database(_, client) => {
                let account_id = *account_id;
                let device_folder = client
                    .conn_and_then(move |conn| {
                        let account = AccountEntity::new(&conn);
                        let folder = FolderEntity::new(&conn);
                        let account_row = account.find_one(&account_id)?;
                        let device_folder =
                            folder.find_device_folder(account_row.row_id)?;
                        let secrets = if let Some(device_folder) =
                            &device_folder
                        {
                            Some(folder.load_secrets(device_folder.row_id)?)
                        } else {
                            None
                        };
                        Ok::<_, sos_database::Error>(
                            device_folder.zip(secrets),
                        )
                    })
                    .await?;

                if let Some((folder, secret_rows)) = device_folder {
                    let record = FolderRecord::from_row(folder).await?;
                    let mut vault = record.into_vault()?;
                    for row in secret_rows {
                        let record = SecretRecord::from_row(row).await?;
                        let SecretRecord {
                            secret_id, commit, ..
                        } = record;
                        vault.insert_entry(secret_id, commit);
                    }
                    Ok(Some(vault))
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Set paths to be for an account identifier.
    pub fn with_account_id(self, account_id: &AccountId) -> Self {
        match self {
            Self::FileSystem(paths) => {
                Self::FileSystem(paths.with_account_id(account_id))
            }
            Self::Database(paths, client) => {
                Self::Database(paths.with_account_id(account_id), client)
            }
        }
    }

    /// List accounts.
    pub async fn list_accounts(&self) -> Result<Vec<PublicIdentity>> {
        match self {
            BackendTarget::FileSystem(paths) => {
                Ok(sos_vault::list_accounts(Some(paths)).await?)
            }
            BackendTarget::Database(_, client) => {
                let account_rows = client
                    .conn_and_then(move |conn| {
                        let account = AccountEntity::new(&conn);
                        account.list_accounts()
                    })
                    .await?;
                let mut accounts = Vec::new();
                for row in account_rows {
                    let record: AccountRecord = row.try_into()?;
                    accounts.push(record.identity);
                }
                Ok(accounts)
            }
        }
    }

    /// List user folders for an account.
    pub async fn list_folders(
        &self,
        account_id: &AccountId,
    ) -> Result<Vec<Summary>> {
        match self {
            BackendTarget::FileSystem(paths) => {
                let paths = paths.with_account_id(account_id);
                Ok(sos_vault::list_local_folders(&paths)
                    .await?
                    .into_iter()
                    .map(|(s, _)| s)
                    .collect())
            }
            BackendTarget::Database(_, client) => {
                let account_id = *account_id;
                let folder_rows = client
                    .conn_and_then(move |conn| {
                        let account = AccountEntity::new(&conn);
                        let folders = FolderEntity::new(&conn);
                        let account_row = account.find_one(&account_id)?;
                        folders.list_user_folders(account_row.row_id)
                    })
                    .await?;
                let mut folders = Vec::new();
                for row in folder_rows {
                    let record = FolderRecord::from_row(row).await?;
                    folders.push(record.summary);
                }
                Ok(folders)
            }
        }
    }

    /// List external files for this backend target.
    #[cfg(feature = "files")]
    pub async fn list_files(&self) -> Result<IndexSet<ExternalFile>> {
        Ok(match self {
            BackendTarget::FileSystem(paths) => {
                sos_external_files::list_external_files(paths).await?
            }
            BackendTarget::Database(paths, _) => {
                sos_external_files::list_external_files(paths).await?
            }
        })
    }
}
