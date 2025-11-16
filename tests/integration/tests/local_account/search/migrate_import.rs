use sos_test_utils::{setup, teardown};
use anyhow::Result;
use sos_account::{Account, LocalAccount};
use sos_migrate::import::{ImportFormat, ImportTarget};
use sos_sdk::prelude::*;
use sos_test_utils::make_client_backend;
use std::path::PathBuf;

/// Tests querying the search index after importing
/// a migration.
#[tokio::test]
async fn local_search_migrate_import() -> Result<()> {
    const TEST_ID: &str = "search_migrate_import";
    //sos_test_utils::init_tracing();

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

    let target = ImportTarget {
        format: ImportFormat::OnePasswordCsv,
        path: PathBuf::from("../fixtures/migrate/1password-export.csv"),
        folder_name: "1password".to_string(),
    };
    account.import_file(target).await?;

    // Can find the updated secret
    let documents = account.query_map("mock", Default::default()).await?;
    assert_eq!(3, documents.len());

    teardown(TEST_ID).await;

    Ok(())
}
