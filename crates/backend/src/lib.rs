#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Backend database and file system storage.
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
    BackendAccountEventLog as AccountEventLog,
    BackendDeviceEventLog as DeviceEventLog, BackendEventLog,
    BackendFolderEventLog as FolderEventLog,
};
pub use folder::Folder;
pub use helpers::extract_vault;
#[cfg(feature = "preferences")]
pub use preferences::BackendPreferences as Preferences;
pub use server_origins::ServerOrigins;
pub use sos_database as database;
pub use sos_filesystem::write_exclusive;
use sos_vault::Summary;
#[cfg(feature = "system-messages")]
pub use system_messages::SystemMessages;
pub use vault_writer::VaultWriter;

#[cfg(feature = "files")]
pub use event_log::BackendFileEventLog as FileEventLog;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;

use sos_core::{AccountId, Paths, PublicIdentity};
use sos_database::{
    async_sqlite::Client,
    entity::{AccountEntity, AccountRecord, FolderEntity, FolderRecord},
    open_file,
};
use std::{fmt, sync::Arc};

#[cfg(feature = "files")]
use {indexmap::IndexSet, sos_core::ExternalFile};

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

impl BackendTarget {
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
