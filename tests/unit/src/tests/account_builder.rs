use anyhow::Result;
use sos_account::AccountBuilder;
use sos_backend::BackendTarget;
use sos_core::Paths;
use sos_database::{db::open_file, migrations::migrate_client};
use sos_login::Identity;
use sos_password::memorable;
use sos_sdk::crypto::AccessKey;
use sos_test_utils::{setup, teardown};

/// Test building a file system account and signing in.
#[tokio::test]
async fn account_builder_fs() -> Result<()> {
    const TEST_ID: &str = "account_builder_fs";
    // crate::test_utils::init_tracing();

    let dirs = setup(TEST_ID, 1).await?;
    let paths = Paths::new_global(&dirs.test_dir);

    let account_name = "fs-account".to_owned();
    let password = memorable();

    let target = BackendTarget::FileSystem(paths.clone());
    let new_account =
        AccountBuilder::new(account_name, password.clone(), target.clone())
            .create_archive(true)
            .create_authenticator(true)
            .create_contacts(true)
            .create_file_password(true)
            .finish()
            .await?;

    let account_id = new_account.account_id;
    let paths = paths.with_account_id(&account_id);

    let mut identity = Identity::new(BackendTarget::FileSystem(paths));
    let access_key: AccessKey = password.into();
    identity
        .sign_in(&new_account.account_id, &access_key)
        .await?;

    identity.sign_out().await?;

    // Folders are not created until a new account
    let target: BackendTarget = identity.into();
    let folders = target.list_folders(&account_id).await?;
    assert!(folders.is_empty());

    teardown(TEST_ID).await;

    Ok(())
}

/// Test building a database account and signing in.
#[tokio::test]
async fn account_builder_db() -> Result<()> {
    const TEST_ID: &str = "account_builder_db";
    // crate::test_utils::init_tracing();

    let dirs = setup(TEST_ID, 1).await?;
    let paths = Paths::new_global(&dirs.test_dir);

    let mut client = open_file(paths.database_file()).await?;
    migrate_client(&mut client).await?;

    let account_name = "db-account".to_owned();
    let password = memorable();

    let target = BackendTarget::Database(client.clone());
    let new_account =
        AccountBuilder::new(account_name, password.clone(), target.clone())
            .create_archive(true)
            .create_authenticator(true)
            .create_contacts(true)
            .create_file_password(true)
            .finish()
            .await?;

    let mut identity = Identity::new(target);
    let access_key: AccessKey = password.into();
    identity
        .sign_in(&new_account.account_id, &access_key)
        .await?;

    identity.sign_out().await?;

    let account_id = new_account.account_id;

    // Folders are not created until a new account
    let target: BackendTarget = identity.into();
    let folders = target.list_folders(&account_id).await?;
    assert!(folders.is_empty());

    teardown(TEST_ID).await;

    Ok(())
}
