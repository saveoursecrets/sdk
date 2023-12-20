use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::sdk::prelude::*;

const TEST_ID: &str = "search_sign_in";

/// Tests querying the search index after signing in 
/// and building a fresh search index.
#[tokio::test]
async fn integration_search_sign_in() -> Result<()> {
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

    let key: AccessKey = password.clone().into();
    account.sign_in(&key).await?;

    let docs = vec![mock::note("note", TEST_ID)];
    account.insert_secrets(docs).await?;

    account.sign_out().await?;
    
    // Sign in and create the new search index
    account.sign_in(&key).await?;
    account.initialize_search_index().await?;
    
    // Check we can find the document
    let documents = account
        .query_map(
            "note",
            Default::default(),
        )
        .await?;
    assert_eq!(1, documents.len());

    teardown(TEST_ID).await;

    Ok(())
}
