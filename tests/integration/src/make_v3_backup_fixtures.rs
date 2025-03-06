use anyhow::Result;
use sos_account::{Account, LocalAccount};
use sos_backend::{archive, BackendTarget};
use sos_database::open_file;
use sos_database_upgrader::archive::upgrade_backup_archive;
use sos_sdk::{prelude::generate_passphrase, Paths};
use std::path::PathBuf;
use tempfile::tempdir_in;

const INPUT: &str = "tests/fixtures/backups/v2/0xba0faea9bbc182e3f4fdb3eea7636b5bb31ea9ac.zip";
const OUTPUT: &str = "tests/fixtures/backups/v3/0xba0faea9bbc182e3f4fdb3eea7636b5bb31ea9ac.zip";

/// Create test fixtures for the v3 backup archives.
///
/// We may need to run this when making changes to the
/// base migration definition.
#[tokio::main]
pub async fn main() -> Result<()> {
    make_single_account().await?;
    make_multi_account().await?;
    Ok(())
}

async fn make_single_account() -> Result<()> {
    let output = PathBuf::from(OUTPUT);
    if output.exists() {
        std::fs::remove_file(&output)?;
    }
    upgrade_backup_archive(INPUT, output).await?;
    Ok(())
}

async fn make_multi_account() -> Result<()> {
    let input = PathBuf::from(OUTPUT);
    let output =
        PathBuf::from("tests/fixtures/backups/v3/multiple-accounts.zip");
    if output.exists() {
        std::fs::remove_file(&output)?;
    }

    let temp = tempdir_in("target")?;
    let paths = Paths::new_client(temp.path());
    let client = open_file(paths.database_file()).await?;
    let target = BackendTarget::Database(paths, client);

    archive::import_backup_archive(&input, &target).await?;

    let account_name = "Multiple Accounts Backup Demo".to_owned();
    let (password, _) = generate_passphrase()?;
    let account =
        LocalAccount::new_account(account_name, password, target.clone())
            .await?;

    sos_backend::archive::export_backup_archive(
        &output,
        &target,
        account.account_id(),
    )
    .await?;

    Ok(())
}
