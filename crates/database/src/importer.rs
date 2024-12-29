use crate::{db, migrations::migrate_db_file, Error, Result};
use async_sqlite::{ClientBuilder, JournalMode};
use sos_sdk::prelude::{Identity, Paths, PublicIdentity};
use std::path::PathBuf;

/// Create the database for an existing account from account paths.
///
/// # Panics
///
/// If the paths are global.
pub async fn import_account(
    paths: &Paths,
    account: &PublicIdentity,
) -> Result<()> {
    if paths.is_global() {
        panic!("import_account does not allow global paths");
    }

    let db_file = paths.database_file();
    if db_file.exists() {
        return Err(Error::DatabaseExists(db_file.to_owned()));
    }

    migrate_db_file(&db_file).await?;

    let mut client = ClientBuilder::new()
        .path(&db_file)
        .journal_mode(JournalMode::Wal)
        .open()
        .await?;

    db::import_account(&mut client, paths, account).await?;

    Ok(())
}

/// Import all accounts found on disc.
pub async fn import_accounts(data_dir: PathBuf) -> Result<()> {
    let paths = Paths::new_global(data_dir);
    let accounts = Identity::list_accounts(Some(&paths)).await?;
    for account in accounts {
        let account_paths =
            Paths::new(paths.documents_dir(), account.address().to_string());
        import_account(&account_paths, &account).await?;
    }
    Ok(())
}
