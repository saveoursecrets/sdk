//! Import filesystem backed accounts into a database.
use crate::{db, migrations::migrate_client, Error, Result};
use async_sqlite::Client;
use sos_core::Paths;
use sos_sdk::prelude::{Identity, PublicIdentity};
use std::path::PathBuf;

/// Create the database for an existing account from account paths.
///
/// # Panics
///
/// If the paths are global.
async fn import_account(
    client: &mut Client,
    paths: &Paths,
    account: &PublicIdentity,
) -> Result<()> {
    if paths.is_global() {
        panic!("import_account does not allow global paths");
    }
    db::import_account(client, paths, account).await?;
    Ok(())
}

/// Import all accounts found on disc.
pub async fn import_accounts(data_dir: PathBuf) -> Result<()> {
    let paths = Paths::new_global(data_dir);

    let db_file = paths.database_file();
    if db_file.exists() {
        return Err(Error::DatabaseExists(db_file.to_owned()));
    }

    let mut client = db::open_file(paths.database_file()).await?;
    migrate_client(&mut client).await?;

    db::import_globals(&mut client, &paths).await?;

    let accounts = Identity::list_accounts(Some(&paths)).await?;
    for account in accounts {
        let account_paths = Paths::new(
            paths.documents_dir(),
            account.account_id().to_string(),
        );
        import_account(&mut client, &account_paths, &account).await?;
    }
    Ok(())
}
