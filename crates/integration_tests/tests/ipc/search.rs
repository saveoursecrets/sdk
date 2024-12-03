use anyhow::Result;
use maplit2::hashmap;
use sos_ipc::{
    local_account_delegate, remove_socket_file, AppIntegration, Error,
    LocalAccountIpcService, LocalAccountSocketServer, SocketClient,
};
use sos_net::sdk::{
    crypto::AccessKey,
    prelude::{
        generate_passphrase, Account, DocumentView, IdentityKind,
        LocalAccount, LocalAccountSwitcher,
    },
    Paths,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::RwLock;

use crate::test_utils::{mock, setup, teardown};

#[tokio::test]
async fn integration_ipc_search() -> Result<()> {
    const TEST_ID: &str = "ipc_search";
    // crate::test_utils::init_tracing();
    //

    let socket_name = format!("{}.sock", TEST_ID);

    // Must clean up the tmp file on MacOS
    remove_socket_file(&socket_name);

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    Paths::scaffold(Some(data_dir.clone())).await?;
    let paths = Paths::new_global(data_dir.clone());

    let account_name = format!("{}_authenticated", TEST_ID);
    let (password, _) = generate_passphrase()?;

    // Create an account and authenticate
    let mut auth_account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
    )
    .await?;
    let key: AccessKey = password.into();
    auth_account.sign_in(&key).await?;

    let default_folder_docs = vec![
        mock::login("foo_login", TEST_ID, generate_passphrase()?.0),
        mock::note("foo_note", "secret"),
        mock::card("foo_card", TEST_ID, "123"),
        mock::bank("foo_bank", TEST_ID, "12-34-56"),
        mock::list(
            "foo_list",
            hashmap! {
                "a" => "1",
                "b" => "2",
            },
        ),
        mock::pem("foo_pem"),
        mock::internal_file(
            "foo_file",
            "file_name.txt",
            "text/plain",
            "file_contents".as_bytes(),
        ),
        mock::link("foo_link", "https://example.com"),
        mock::password("foo_password", generate_passphrase()?.0),
        mock::age("foo_age"),
        mock::identity("foo_identity", IdentityKind::IdCard, "1234567890"),
        mock::totp("foo_totp"),
        mock::contact("foo_contact", "Jane Doe"),
        mock::page("foo_page", "Title", "Body"),
    ];

    let total_docs = default_folder_docs.len();

    // Create a document for each secret type
    auth_account.insert_secrets(default_folder_docs).await?;

    let auth_address = auth_account.address().clone();

    // Add the accounts
    let mut accounts = LocalAccountSwitcher::new_with_options(Some(paths));
    accounts.add_account(auth_account);
    accounts.switch_account(&auth_address);

    let ipc_accounts = Arc::new(RwLock::new(accounts));

    let (delegate, _commands) = local_account_delegate(16);

    // Start the IPC service
    let service = Arc::new(RwLock::new(LocalAccountIpcService::new(
        ipc_accounts,
        delegate,
        Default::default(),
    )));

    let server_socket_name = socket_name.clone();
    tokio::task::spawn(async move {
        LocalAccountSocketServer::listen(&server_socket_name, service)
            .await?;
        Ok::<(), Error>(())
    });

    tokio::time::sleep(Duration::from_millis(250)).await;

    let mut client = SocketClient::connect(&socket_name).await?;

    // Search for a needle
    let mut results = client.search("foo", Default::default()).await?;
    assert_eq!(1, results.len());
    let documents = results.remove(0).1;
    assert_eq!(total_docs, documents.len());

    // Query a search index view
    let views = vec![DocumentView::All {
        ignored_types: None,
    }];
    let mut results = client.query_view(views, Default::default()).await?;
    assert_eq!(1, results.len());
    let documents = results.remove(0).1;
    assert_eq!(total_docs, documents.len());

    teardown(TEST_ID).await;

    Ok(())
}
