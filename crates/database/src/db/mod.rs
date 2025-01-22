//! Database entities.
mod account;
mod audit;
mod event;
// #[cfg(feature = "files")]
// mod file;
mod folder;
mod import;
#[cfg(feature = "preferences")]
mod preference;
mod server;
#[cfg(feature = "system-messages")]
mod system_message;

pub use account::{AccountEntity, AccountRecord, AccountRow};
pub use audit::{AuditEntity, AuditRecord, AuditRow};
pub use event::{CommitRecord, EventEntity, EventRecordRow, EventTable};
// #[cfg(feature = "files")]
// pub use file::FileEntity;
pub use folder::{
    FolderEntity, FolderRecord, FolderRow, SecretRecord, SecretRow,
};
#[cfg(feature = "preferences")]
pub use preference::{PreferenceEntity, PreferenceRow};
pub use server::{ServerEntity, ServerRow};
#[cfg(feature = "system-messages")]
pub use system_message::{SystemMessageEntity, SystemMessageRow};

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
