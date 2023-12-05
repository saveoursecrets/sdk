use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_net::sdk::{prelude::*, vfs};

const TEST_ID: &str = "migrate_export";

/// Tests exporting an archive of plain text secrets.
#[tokio::test]
async fn integration_migrate_export() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    UserPaths::scaffold(Some(data_dir.clone())).await?;
    UserPaths::new_global(data_dir.clone());

    let (mut account, _new_account) = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        None,
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
