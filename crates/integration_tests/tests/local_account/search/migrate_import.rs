use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_net::sdk::prelude::*;
use std::path::PathBuf;

/// Tests querying the search index after importing
/// a migration.
#[tokio::test]
async fn local_search_migrate_import() -> Result<()> {
    const TEST_ID: &str = "search_migrate_import";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
    )
    .await?;

    let key: AccessKey = password.into();
    account.sign_in(&key).await?;

    let target = ImportTarget {
        format: ImportFormat::OnePasswordCsv,
        path: PathBuf::from("tests/fixtures/migrate/1password-export.csv"),
        folder_name: "1password".to_string(),
    };
    account.import_file(target).await?;

    // Can find the updated secret
    let documents = account.query_map("mock", Default::default()).await?;
    assert_eq!(3, documents.len());

    teardown(TEST_ID).await;

    Ok(())
}
