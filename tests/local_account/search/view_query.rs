use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use maplit2::{hashmap, hashset};
use sos_net::sdk::prelude::*;

/// Tests querying the search index using views and search queries.
#[tokio::test]
async fn local_search_view_query() -> Result<()> {
    const TEST_ID: &str = "search_view_query";
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

    let key: AccessKey = password.clone().into();
    account.sign_in(&key).await?;
    let default_folder = account.default_folder().await.unwrap();
    let archive_folder = account.archive_folder().await.unwrap();

    let default_folder_docs = vec![
        mock::login("login", TEST_ID, generate_passphrase()?.0),
        mock::note("note", "secret"),
        mock::card("card", TEST_ID, "123"),
        mock::bank("bank", TEST_ID, "12-34-56"),
        mock::list(
            "list",
            hashmap! {
                "a" => "1",
                "b" => "2",
            },
        ),
        mock::pem("pem"),
        mock::internal_file(
            "file",
            "file_name.txt",
            "text/plain",
            "file_contents".as_bytes(),
        ),
        mock::link("link", "https://example.com"),
        mock::password("password", generate_passphrase()?.0),
        mock::age("age"),
        mock::identity("identity", IdentityKind::IdCard, "1234567890"),
        mock::totp("totp"),
        mock::contact("contact", "Jane Doe"),
        mock::page("page", "Title", "Body"),
    ];

    let (mut fav_meta, fav_secret) = mock::note("favorite", "secret");
    fav_meta.set_favorite(true);
    fav_meta.set_tags(hashset!["new_folder".to_owned()]);
    let (mut tag_meta, tag_secret) = mock::note("tag", "secret");
    tag_meta.set_tags(hashset!["new_folder".to_owned()]);
    let new_folder_docs = vec![
        mock::login("alt-login", TEST_ID, generate_passphrase()?.0),
        (fav_meta, fav_secret),
        (tag_meta, tag_secret),
    ];

    let total_docs = default_folder_docs.len() + new_folder_docs.len();

    // Create a document for each secret type
    let bulk = account.insert_secrets(default_folder_docs).await?;
    let ids: Vec<_> = bulk.results.into_iter().map(|r| r.id).collect();

    // Secret we will move to the archive
    let card_id = *ids.get(2).unwrap();

    // Create a folder and add secrets to the other folder
    let folder_name = "folder_name";
    let FolderCreate { folder, .. } =
        account.create_folder(folder_name.to_string()).await?;

    account.open_folder(&folder).await?;
    account.insert_secrets(new_folder_docs).await?;

    // Get all documents in the index.
    let documents =
        account.query_view(vec![Default::default()], None).await?;
    assert_eq!(total_docs, documents.len());

    // Get all documents ignoring some types
    let documents = account
        .query_view(
            vec![DocumentView::All {
                ignored_types: Some(vec![SecretType::Account]),
            }],
            None,
        )
        .await?;
    assert_eq!(15, documents.len());

    // Find favorites
    let documents = account
        .query_view(vec![DocumentView::Favorites], None)
        .await?;
    assert_eq!(1, documents.len());

    // Query by specific document identifiers
    let identifiers = (&ids[0..4]).into_iter().map(|id| *id).collect();
    let documents = account
        .query_view(
            vec![DocumentView::Documents {
                vault_id: *default_folder.id(),
                identifiers,
            }],
            None,
        )
        .await?;
    assert_eq!(4, documents.len());

    // Find contacts
    let documents = account
        .query_view(
            vec![DocumentView::Contact {
                include_types: None,
            }],
            None,
        )
        .await?;
    assert_eq!(1, documents.len());

    // Find by type
    let documents = account
        .query_view(vec![DocumentView::TypeId(SecretType::Account)], None)
        .await?;
    assert_eq!(2, documents.len());

    // Find all in a specific folder
    let documents = account
        .query_view(vec![DocumentView::Vault(*default_folder.id())], None)
        .await?;
    assert_eq!(14, documents.len());

    // Find by tags
    let documents = account
        .query_view(
            vec![DocumentView::Tags(vec!["new_folder".to_owned()])],
            None,
        )
        .await?;
    assert_eq!(2, documents.len());

    // Move a secret to the archive
    account
        .archive(&default_folder, &card_id, Default::default())
        .await?;

    // Query all documents but ignore items
    // in the archive
    let documents = account
        .query_view(
            vec![Default::default()],
            Some(ArchiveFilter {
                id: *archive_folder.id(),
                include_documents: false,
            }),
        )
        .await?;
    assert_eq!(total_docs - 1, documents.len());

    // Query all documents and explicitly include items
    // in the archive
    let documents = account
        .query_view(
            vec![Default::default()],
            Some(ArchiveFilter {
                id: *archive_folder.id(),
                include_documents: true,
            }),
        )
        .await?;
    assert_eq!(total_docs, documents.len());

    // Gets the two login secrets, "login" and "alt-login"
    let documents = account.query_map("log", Default::default()).await?;
    assert_eq!(2, documents.len());

    // Just the "login" secret as we filter by folder
    let documents = account
        .query_map(
            "log",
            QueryFilter {
                folders: vec![*default_folder.id()],
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(1, documents.len());

    // Gets the "age" and "page" secrets
    let documents = account.query_map("age", Default::default()).await?;
    assert_eq!(2, documents.len());

    // Just the "page" secret as we filter by type
    let documents = account
        .query_map(
            "age",
            QueryFilter {
                types: vec![SecretType::Page],
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(1, documents.len());

    // Empty query gets all documents
    let documents = account.query_map("", Default::default()).await?;
    assert_eq!(total_docs, documents.len());

    // Empty query with a tag filter
    // gets us those tags only
    let documents = account
        .query_map(
            "",
            QueryFilter {
                tags: vec!["new_folder".to_owned()],
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(2, documents.len());

    teardown(TEST_ID).await;

    Ok(())
}
