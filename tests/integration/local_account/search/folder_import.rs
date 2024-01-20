use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::sdk::prelude::*;

/// Tests querying the search index after importing a folder.
#[tokio::test]
async fn integration_search_folder_import() -> Result<()> {
    const TEST_ID: &str = "search_folder_import";
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
    let folder = account.default_folder().await.unwrap();

    // Create a secret
    let (meta, secret) = mock::note("note", TEST_ID);
    let SecretChange { id, .. } = account
        .create_secret(meta, secret, Default::default())
        .await?;

    // Export a folder
    let (folder_password, _) = generate_passphrase()?;
    let exported = data_dir.join("exported.vault");
    account
        .export_folder(
            &exported,
            &folder,
            folder_password.clone().into(),
            true,
        )
        .await?;
    assert!(vfs::try_exists(&exported).await?);

    // Delete the secret
    account.delete_secret(&id, Default::default()).await?;

    // Import the folder we exported
    account
        .import_folder(&exported, folder_password.into(), false)
        .await?;

    // Check we can find the secret
    let documents = account.query_map("note", Default::default()).await?;
    assert_eq!(1, documents.len());

    teardown(TEST_ID).await;

    Ok(())
}
