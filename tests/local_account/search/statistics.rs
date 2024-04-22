use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::sdk::prelude::*;

/// Tests the statistics maintained whilst modifting the search index.
#[tokio::test]
async fn local_search_statistics() -> Result<()> {
    const TEST_ID: &str = "search_statistics";
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

    let default_folder = account.default_folder().await.unwrap();

    // Create a secret
    let (meta, secret) = mock::note("note", TEST_ID);
    let SecretChange { id, .. } = account
        .create_secret(meta, secret, Default::default())
        .await?;

    // Creating increments the count
    let count = account.document_count().await?;
    assert_eq!(1, *count.vaults().get(default_folder.id()).unwrap());
    assert_eq!(1, *count.kinds().get(&SecretType::Note.into()).unwrap());

    // Deleting decrements the count
    account.delete_secret(&id, Default::default()).await?;

    let count = account.document_count().await?;
    assert_eq!(0, *count.vaults().get(default_folder.id()).unwrap());
    assert_eq!(0, *count.kinds().get(&SecretType::Note.into()).unwrap());

    // Create multiple file secrets
    // SEE: https://github.com/saveoursecrets/sdk/issues/400
    let (meta, secret, _) = mock::file_text_secret()?;
    account
        .create_secret(meta.clone(), secret.clone(), Default::default())
        .await?;

    let count = account.document_count().await?;
    assert_eq!(1, *count.vaults().get(default_folder.id()).unwrap());
    assert_eq!(1, *count.kinds().get(&SecretType::File.into()).unwrap());

    let SecretChange { id, .. } = account
        .create_secret(meta.clone(), secret.clone(), Default::default())
        .await?;

    let count = account.document_count().await?;
    assert_eq!(2, *count.vaults().get(default_folder.id()).unwrap());
    assert_eq!(2, *count.kinds().get(&SecretType::File.into()).unwrap());

    account.delete_secret(&id, Default::default()).await?;

    let count = account.document_count().await?;
    assert_eq!(1, *count.vaults().get(default_folder.id()).unwrap());
    assert_eq!(1, *count.kinds().get(&SecretType::File.into()).unwrap());

    println!("{:#?}", count);

    teardown(TEST_ID).await;

    Ok(())
}
