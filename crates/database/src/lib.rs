#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![cfg_attr(all(doc, CHANNEL_NIGHTLY), feature(doc_auto_cfg))]
//! Database storage layer for the [Save Our Secrets](https://saveoursecrets.com) SDK.
#[cfg(all(feature = "archive", feature = "sqlite"))]
pub mod archive;
#[cfg(all(feature = "audit", feature = "sqlite"))]
pub mod audit_provider;
#[cfg(feature = "sqlite")]
pub mod entity;
#[cfg(feature = "sqlite")]
pub mod event_log;
#[cfg(feature = "sqlite")]
pub mod migrations;
#[cfg(all(feature = "sqlite", feature = "preferences"))]
mod preferences;
#[cfg(all(feature = "sqlite", feature = "system-messages"))]
mod system_messages;

#[cfg(feature = "sqlite")]
mod server_origins;

#[cfg(feature = "sqlite")]
mod vault_writer;

#[cfg(feature = "sqlite")]
pub use event_log::{
    AccountEventLog, DatabaseEventLog, DeviceEventLog, EventLogOwner,
    FolderEventLog,
};

#[cfg(all(feature = "sqlite", feature = "preferences"))]
pub use preferences::PreferenceProvider;

#[cfg(all(feature = "sqlite", feature = "system-messages"))]
pub use system_messages::SystemMessagesProvider;

#[cfg(feature = "sqlite")]
pub use server_origins::ServerOrigins;

#[cfg(feature = "sqlite")]
pub use vault_writer::VaultDatabaseWriter;

#[cfg(all(feature = "sqlite", feature = "files"))]
pub use event_log::FileEventLog;

mod error;
pub use async_sqlite;
pub use error::Error;

/// Result type for the library.
pub(crate) type Result<T> = std::result::Result<T, Error>;

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

/// Open a database file from a specific journal mode.
pub async fn open_file_with_journal_mode(
    path: impl AsRef<Path>,
    mode: JournalMode,
) -> Result<Client> {
    Ok(ClientBuilder::new()
        .path(path.as_ref())
        .journal_mode(mode)
        .open()
        .await?)
}

/// Open an in-memory database and run migrations.
pub async fn open_memory() -> Result<Client> {
    let mut client = ClientBuilder::new().open().await?;
    crate::migrations::migrate_client(&mut client).await?;
    Ok(client)
}

#[cfg(debug_assertions)]
#[allow(dead_code)]
pub(crate) fn dump_rows<C>(
    conn: C,
    table: &str,
) -> std::result::Result<(), async_sqlite::rusqlite::Error>
where
    C: std::ops::Deref<Target = async_sqlite::rusqlite::Connection>,
{
    println!("--- BEGIN DUMP ---");
    let mut stmt = conn.prepare(&format!(
        r#"
            SELECT * FROM {}
        "#,
        table
    ))?;
    let mut rows = stmt.query([])?;
    while let Ok(Some(row)) = rows.next() {
        println!("{:#?}", row);
    }
    println!("--- END DUMP ---");
    Ok(())
}
