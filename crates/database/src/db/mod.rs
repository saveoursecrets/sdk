//! Database entities.
mod account;
mod audit;
mod event;
#[cfg(feature = "files")]
mod file;
mod folder;
mod import;
mod preference;
mod server;

pub use account::{AccountEntity, AccountRecord};
pub use audit::AuditEntity;
pub use event::{CommitRecord, EventEntity, EventTable};
#[cfg(feature = "files")]
pub use file::FileEntity;
pub use folder::{FolderEntity, FolderRecord, SecretRecord};
pub use preference::PreferenceEntity;
pub use server::ServerEntity;

pub(crate) use import::{import_account, import_globals};

use crate::Result;
use async_sqlite::{Client, ClientBuilder, JournalMode};
use std::path::Path;

/// Open a database file from a path with WAL journal mode enabled.
pub async fn open_file(path: impl AsRef<Path>) -> Result<Client> {
    Ok(ClientBuilder::new()
        .path(path.as_ref())
        .journal_mode(JournalMode::Wal)
        .open()
        .await?)
}

/// Open an in-memory database and run migrations.
pub async fn open_memory() -> Result<Client> {
    let mut client = ClientBuilder::new().open().await?;
    crate::migrations::migrate_client(&mut client).await?;
    Ok(client)
}
