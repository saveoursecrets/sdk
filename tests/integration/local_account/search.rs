use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use maplit2::{hashmap, hashset};
use sos_net::sdk::{
    account::{
        search::{ArchiveFilter, DocumentView, QueryFilter},
        LocalAccount, UserPaths,
    },
    passwd::diceware::generate_passphrase,
    vault::secret::{IdentityKind, SecretType},
};

const TEST_ID: &str = "search";

/// Tests querying the search index.
#[tokio::test]
async fn integration_search() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    UserPaths::scaffold(Some(data_dir.clone())).await?;
    UserPaths::new_global(data_dir.clone());

    let (mut account, new_account) = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    let default_folder = new_account.default_folder();
    account.sign_in(password.clone()).await?;
    account.open_folder(&default_folder).await?;

    // Create a document for each secret type
    let results = account
        .insert(vec![
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
        ])
        .await?;

    let ids: Vec<_> = results.into_iter().map(|r| r.0).collect();

    // Create a folder and add secrets to the other folder
    let folder_name = "folder_name";
    let (folder, _, _, _) =
        account.create_folder(folder_name.to_string()).await?;
    account.open_folder(&folder).await?;
    let (mut fav_meta, fav_secret) = mock::note("favorite", "secret");
    fav_meta.set_favorite(true);

    let (mut tag_meta, tag_secret) = mock::note("tag", "secret");
    tag_meta.set_tags(hashset!["notes".to_owned()]);
    account
        .insert(vec![
            mock::login("alt-login", TEST_ID, generate_passphrase()?.0),
            (fav_meta, fav_secret),
            (tag_meta, tag_secret),
        ])
        .await?;

    // Get all documents in the index.
    let documents = account
        .index()?
        .query_view(
            vec![DocumentView::All {
                ignored_types: None,
            }],
            None,
        )
        .await?;
    assert_eq!(17, documents.len());

    // Get all documents ignoring some types
    let documents = account
        .index()?
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
        .index()?
        .query_view(vec![DocumentView::Favorites], None)
        .await?;
    assert_eq!(1, documents.len());

    // Query by specific document identifiers
    let identifiers = (&ids[0..4]).into_iter().map(|id| *id).collect();
    let documents = account
        .index()?
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
        .index()?
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
        .index()?
        .query_view(vec![DocumentView::TypeId(SecretType::Account)], None)
        .await?;
    assert_eq!(2, documents.len());

    // Find all in a specific folder
    let documents = account
        .index()?
        .query_view(vec![DocumentView::Vault(*default_folder.id())], None)
        .await?;
    assert_eq!(14, documents.len());

    // Find by tags
    let documents = account
        .index()?
        .query_view(vec![DocumentView::Tags(vec!["notes".to_owned()])], None)
        .await?;
    assert_eq!(1, documents.len());

    // Gets the two login secrets, "login" and "alt-login"
    let documents = account
        .index()?
        .query_map("log", Default::default())
        .await?;
    assert_eq!(2, documents.len());

    // Just the "login" secret as we filter by folder
    let documents = account
        .index()?
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
    let documents = account
        .index()?
        .query_map("age", Default::default())
        .await?;
    assert_eq!(2, documents.len());

    // Just the "page" secret as we filter by type
    let documents = account
        .index()?
        .query_map(
            "age",
            QueryFilter {
                types: vec![SecretType::Page],
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(1, documents.len());

    println!("{:#?}", documents.len());

    teardown(TEST_ID).await;

    Ok(())
}
