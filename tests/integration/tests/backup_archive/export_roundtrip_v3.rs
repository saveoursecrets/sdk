use super::assert_roundtrip;
use anyhow::Result;
use sos_backend::BackendTarget;
use sos_core::Paths;
use sos_database::{migrations::migrate_client, open_file};
use sos_password::diceware::generate_passphrase;
use sos_test_utils::{setup, teardown};

/// Test exporting a v3 backup archive using the database
/// backend and then importing it.
#[tokio::test]
async fn backup_export_roundtrip_v3() -> Result<()> {
    const TEST_ID: &str = "backup_export_roundtrip_v3";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    Paths::scaffold(&data_dir).await?;

    let paths = Paths::new_client(&data_dir);
    let mut client = open_file(paths.database_file()).await?;
    migrate_client(&mut client).await?;
    let target = BackendTarget::Database(paths.clone(), client);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    assert_roundtrip(account_name, password, target).await?;

    teardown(TEST_ID).await;

    Ok(())
}
