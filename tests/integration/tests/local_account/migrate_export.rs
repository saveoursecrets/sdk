use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_account::{Account, LocalAccount};
use sos_sdk::prelude::*;
use sos_test_utils::make_client_backend;
use sos_vfs as vfs;

/// Tests exporting an archive of plain text secrets.
#[tokio::test]
async fn local_migrate_export() -> Result<()> {
    const TEST_ID: &str = "migrate_export";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    let paths = Paths::new_client(&data_dir);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        make_client_backend(&paths).await?,
    )
    .await?;

    let key: AccessKey = password.into();
    account.sign_in(&key).await?;

    let zip = data_dir.join("export.zip");
    account.export_unsafe_archive(&zip).await?;
    assert!(vfs::try_exists(&zip).await?);

    // TODO: assert on exported data!

    teardown(TEST_ID).await;

    Ok(())
}
