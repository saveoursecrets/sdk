use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::sdk::prelude::*;

/// Tests querying the search index using a websites view.
#[tokio::test]
async fn local_search_view_query_websites() -> Result<()> {
    const TEST_ID: &str = "search_view_query_websites";
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
    let default_folder = account.default_folder().await.unwrap();
    account.open_folder(&default_folder).await?;

    let default_folder_docs = vec![
        mock::login(
            "login:no_websites",
            "me@example.com",
            generate_passphrase()?.0,
        ),
        mock::login_websites(
            "login:apple.com",
            "me@apple.com",
            generate_passphrase()?.0,
            vec![
                "https://apple.com".parse()?,
                "https://developer.apple.com".parse()?,
            ],
        ),
        mock::login_websites(
            "login:google.com",
            "me@google.com",
            generate_passphrase()?.0,
            vec!["https://google.com".parse()?, "https://gmail.com".parse()?],
        ),
        // Origin match
        mock::login_websites(
            "login:a1.com",
            "me@a.com",
            generate_passphrase()?.0,
            vec!["https://a.com/foo".parse()?],
        ),
        mock::login_websites(
            "login:a2.com",
            "me@a.com",
            generate_passphrase()?.0,
            vec!["https://a.com/bar".parse()?],
        ),
        // Origin mismatch (different schemes)
        mock::login_websites(
            "login:b1.com",
            "me@a.com",
            generate_passphrase()?.0,
            vec!["https://b.com/foo".parse()?],
        ),
        mock::login_websites(
            "login:b2.com",
            "me@a.com",
            generate_passphrase()?.0,
            vec!["http://b.com/bar".parse()?],
        ),
    ];

    account.insert_secrets(default_folder_docs).await?;

    // Find all documents with associated websites
    let documents = account
        .query_view(
            &[DocumentView::Websites {
                matches: None,
                exact: true,
            }],
            None,
        )
        .await?;
    assert_eq!(6, documents.len());

    // Find documents with an exact website match
    let documents = account
        .query_view(
            &[DocumentView::Websites {
                matches: Some(vec!["https://apple.com".parse()?]),
                exact: true,
            }],
            None,
        )
        .await?;
    assert_eq!(1, documents.len());

    // Find documents by origin match
    let documents = account
        .query_view(
            &[DocumentView::Websites {
                matches: Some(vec!["https://a.com".parse()?]),
                exact: false,
            }],
            None,
        )
        .await?;
    assert_eq!(2, documents.len());

    let mut websites: Vec<&str> = Vec::new();
    for doc in &documents {
        if let Some(sites) = doc.extra().websites() {
            websites.append(&mut sites.into_iter().map(|u| &u[..]).collect());
        }
    }

    assert!(websites.contains(&"https://a.com/foo"));
    assert!(websites.contains(&"https://a.com/bar"));

    // Find documents by origin (ignoring mismatched scheme)
    let documents = account
        .query_view(
            &[DocumentView::Websites {
                matches: Some(vec!["https://b.com".parse()?]),
                exact: false,
            }],
            None,
        )
        .await?;
    assert_eq!(1, documents.len());

    teardown(TEST_ID).await;

    Ok(())
}
