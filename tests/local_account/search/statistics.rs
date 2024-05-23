use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use maplit2::hashset;
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

    let mut account = LocalAccount::new_account_with_builder(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        |builder| builder.create_archive(true).create_file_password(true),
    )
    .await?;

    let key: AccessKey = password.into();
    account.sign_in(&key).await?;
    account.initialize_search_index().await?;

    let default_folder = account.default_folder().await.unwrap();
    let archive_folder = account.archive_folder().await.unwrap();

    // Create a secret note
    let (meta, secret) = mock::note("note", TEST_ID);
    let SecretChange { id, .. } = account
        .create_secret(meta, secret, Default::default())
        .await?;

    // Creating increments the count
    let count = account.document_count().await?;
    assert_eq!(1, *count.vaults().get(default_folder.id()).unwrap());
    assert_eq!(1, *count.kinds().get(&SecretType::Note.into()).unwrap());

    // Mark a secret as favorite
    let (mut data, _) = account.read_secret(&id, None).await?;
    data.meta_mut().set_favorite(true);
    account
        .update_secret(&id, data.into(), None, Default::default(), None)
        .await?;
    let count = account.document_count().await?;
    assert_eq!(1, *count.vaults().get(default_folder.id()).unwrap());
    assert_eq!(1, *count.kinds().get(&SecretType::Note.into()).unwrap());
    assert_eq!(1, count.favorites());

    // Unmark a secret as favorite
    let (mut data, _) = account.read_secret(&id, None).await?;
    data.meta_mut().set_favorite(false);
    account
        .update_secret(&id, data.into(), None, Default::default(), None)
        .await?;
    let count = account.document_count().await?;
    assert_eq!(1, *count.vaults().get(default_folder.id()).unwrap());
    assert_eq!(1, *count.kinds().get(&SecretType::Note.into()).unwrap());
    assert_eq!(0, count.favorites());

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

    // Deleting decrements the count
    account.delete_secret(&id, Default::default()).await?;
    let count = account.document_count().await?;
    assert_eq!(1, *count.vaults().get(default_folder.id()).unwrap());
    assert_eq!(1, *count.kinds().get(&SecretType::File.into()).unwrap());

    // Create a secret login and archive/unarchive
    let (meta, secret) =
        mock::login("login", TEST_ID, generate_passphrase()?.0);
    let SecretChange { id, .. } = account
        .create_secret(meta.clone(), secret, Default::default())
        .await?;
    let count = account.document_count().await?;
    assert_eq!(2, *count.vaults().get(default_folder.id()).unwrap());
    assert_eq!(1, *count.kinds().get(&SecretType::Account.into()).unwrap());
    let SecretMove { id, .. } = account
        .archive(&default_folder, &id, Default::default())
        .await?;
    let count = account.document_count().await?;
    assert_eq!(1, *count.vaults().get(default_folder.id()).unwrap());
    assert_eq!(1, *count.vaults().get(archive_folder.id()).unwrap());
    account.unarchive(&id, &meta, Default::default()).await?;
    let count = account.document_count().await?;
    assert_eq!(2, *count.vaults().get(default_folder.id()).unwrap());
    assert_eq!(0, *count.vaults().get(archive_folder.id()).unwrap());

    // Secret with tags
    let (mut meta, secret) = mock::note("tag", "secret");
    let tag_name = "mock_tag";
    meta.set_tags(hashset![tag_name.to_owned()]);
    account
        .create_secret(meta, secret, Default::default())
        .await?;

    let count = account.document_count().await?;
    assert_eq!(1, *count.tags().get(tag_name).unwrap());

    teardown(TEST_ID).await;

    Ok(())
}
