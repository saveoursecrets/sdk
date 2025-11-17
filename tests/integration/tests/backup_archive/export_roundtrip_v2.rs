use super::assert_roundtrip;
use anyhow::Result;
use sos_backend::BackendTarget;
use sos_core::Paths;
use sos_password::diceware::generate_passphrase;
use sos_test_utils::{setup, teardown};

/// Test exporting a v2 backup archive using the file
/// system backend and then importing it.
#[tokio::test]
async fn backup_export_roundtrip_v2() -> Result<()> {
    const TEST_ID: &str = "backup_export_roundtrip_v2";
    //sos_test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    Paths::scaffold(&data_dir).await?;

    let paths = Paths::new_client(&data_dir);
    let target = BackendTarget::FileSystem(paths.clone());

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    assert_roundtrip(account_name, password, target).await?;

    teardown(TEST_ID).await;

    Ok(())
}
