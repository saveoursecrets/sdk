use anyhow::Result;
use secrecy::SecretString;
use sos_account::{Account, FolderCreate, LocalAccount};
use sos_backend::BackendTarget;
use sos_client_storage::NewFolderOptions;
use sos_database::async_sqlite::Client;
use sos_database::{
    entity::{
        AccountRecord, RecipientEntity, RecipientRecord, SharedFolderEntity,
    },
    migrations::migrate_client,
    open_file,
};
use sos_sdk::prelude::*;
use sos_test_utils::{default_server_paths, setup, teardown, TestDirs};

/// Test managing recipient information for an account.
#[tokio::test]
async fn database_entity_manage_recipient() -> Result<()> {
    const TEST_ID: &str = "database_entity_manage_recipient";
    // sos_test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    // Configure the db client
    let paths = Paths::new_client(&data_dir);
    let mut client = open_file(paths.database_file()).await?;
    migrate_client(&mut client).await?;
    let target = BackendTarget::Database(paths, client.clone());

    let (_account_record, account, _, _) =
        super::prepare_local_db_account(&target, TEST_ID).await?;

    let account_id = *account.account_id();
    let recipient_name = "Example";
    let recipient_email = "user@example.com";
    let recipient_public_key = "<mock public key>";

    // Initial insert on creating recipient information
    let recipient_id = client
        .conn_mut_and_then(move |conn| {
            let mut entity = SharedFolderEntity::new(conn);
            let recipient_id = entity.upsert_recipient(
                account_id,
                recipient_name.to_string(),
                Some(recipient_email.to_string()),
                recipient_public_key.to_string(),
            )?;
            Ok::<_, anyhow::Error>(recipient_id)
        })
        .await?;

    // Get the recipient record
    let recipient_record: RecipientRecord = client
        .conn_mut_and_then(move |conn| {
            let mut entity = SharedFolderEntity::new(conn);
            entity.find_recipient(account_id)
        })
        .await?
        .expect("to find recipient record");

    assert_eq!(recipient_id, recipient_record.row_id);
    assert_eq!(recipient_name, &recipient_record.recipient_name);
    assert_eq!(
        Some(recipient_email),
        recipient_record.recipient_email.as_deref()
    );
    assert_eq!(recipient_public_key, &recipient_record.recipient_public_key);

    let new_recipient_name = "Example";
    let new_recipient_email = "new-user@example.com";
    let new_recipient_public_key = "<new mock public key>";

    // Update recipient information for an account
    let new_recipient_id = client
        .conn_mut_and_then(move |conn| {
            let mut entity = SharedFolderEntity::new(conn);
            let recipient_id = entity.upsert_recipient(
                account_id,
                new_recipient_name.to_string(),
                Some(new_recipient_email.to_string()),
                new_recipient_public_key.to_string(),
            )?;
            Ok::<_, anyhow::Error>(recipient_id)
        })
        .await?;
    assert_eq!(recipient_id, new_recipient_id);

    // Get the recipient record
    let recipient_record: RecipientRecord = client
        .conn_mut_and_then(move |conn| {
            let mut entity = SharedFolderEntity::new(conn);
            entity.find_recipient(account_id)
        })
        .await?
        .expect("to find recipient record");

    assert_eq!(new_recipient_id, recipient_record.row_id);
    assert_eq!(new_recipient_name, &recipient_record.recipient_name);
    assert_eq!(
        Some(new_recipient_email),
        recipient_record.recipient_email.as_deref()
    );
    assert_eq!(
        new_recipient_public_key,
        &recipient_record.recipient_public_key
    );

    teardown(TEST_ID).await;

    Ok(())
}

/// Test sending a folder invite to another recipient.
#[tokio::test]
async fn database_entity_send_folder_invite() -> Result<()> {
    const TEST_ID: &str = "database_entity_send_folder_invite";
    // sos_test_utils::init_tracing();

    // This test is outside of the context of the network however
    // the data source must be shared between clients so we configure
    // a shared database
    let server_paths = default_server_paths(TEST_ID).await?;
    let mut server = open_file(server_paths.database_file()).await?;
    migrate_client(&mut server).await?;

    let dirs = setup(TEST_ID, 2).await?;

    #[inline(always)]
    async fn prepare_db(
        dirs: &TestDirs,
        index: usize,
        server: Client,
    ) -> Result<(AccountRecord, LocalAccount, Summary, SecretString)> {
        let name = format!("{}_account_{}", TEST_ID, index);
        let paths = Paths::new_client(dirs.clients.get(index).unwrap());
        let target = BackendTarget::Database(paths, server);
        super::prepare_local_db_account(&target, &name).await
    }

    let (_, mut account1, _, _) =
        prepare_db(&dirs, 0, server.clone()).await?;
    let (_, account2, _, _) = prepare_db(&dirs, 1, server.clone()).await?;

    // Both accounts must have enabled sharing by
    // creating recipient information
    {
        let recipients_info = [
            (*account1.account_id(), "name_one", "one@example.com", "<public key 1>"),
            (*account2.account_id(), "name_two", "two@example.com", "<public key 2>"),
        ];

        // Register each account as a recipient for sharing
        for (account_id, name, email, public_key) in recipients_info.into_iter() {
            server
                .conn_mut_and_then(move |conn| {
                    let mut entity = SharedFolderEntity::new(conn);
                    let recipient_id = entity.upsert_recipient(
                        account_id,
                        name.to_string(),
                        Some(email.to_string()),
                        public_key.to_string(),
                    )?;
                    Ok::<_, anyhow::Error>(recipient_id)
                })
                .await?;
        }
    }

    // First account is the owner of the shared folder
    let folder_name = "shared_folder";
    let FolderCreate { folder, .. } = account1
        .create_shared_folder(NewFolderOptions::new(folder_name.to_string()))
        .await?;
    let shared_folder_id = *folder.id();

    // Search for recipients
    let mut found_recipients = server
        .conn_and_then(move |conn| {
            let mut entity = RecipientEntity::new(&conn);
            Ok::<_, anyhow::Error>(entity.search_recipients("two")?)
        })
        .await?;

    assert_eq!(1, found_recipients.len());

    let from_account_id = *account1.account_id();
    let to_account_id = *account2.account_id();

    // Invite the found recipient
    let to_recipient = found_recipients.remove(0);
    server
        .conn_mut_and_then(move |conn| {
            let mut entity = SharedFolderEntity::new(conn);
            Ok::<_, anyhow::Error>(entity.invite_recipient(
                &from_account_id,
                &to_recipient.recipient_public_key,
                &shared_folder_id,
            )?)
        })
        .await?;

    // Check the sent invites list for the sender (account1)
    let mut sent_invites = server
        .conn_mut_and_then(move |conn| {
            let mut entity = SharedFolderEntity::new(conn);
            Ok::<_, anyhow::Error>(
                entity.sent_folder_invites(&from_account_id, None)?,
            )
        })
        .await?;
    assert_eq!(1, sent_invites.len());

    // Check the received invites list for the receiver (account2)
    let mut received_invites = server
        .conn_mut_and_then(move |conn| {
            let mut entity = SharedFolderEntity::new(conn);
            Ok::<_, anyhow::Error>(
                entity.received_folder_invites(&to_account_id, None)?,
            )
        })
        .await?;
    assert_eq!(1, received_invites.len());

    let sent_invite = sent_invites.remove(0);
    let received_invite = received_invites.remove(0);
       
    assert_eq!(sent_invite.row_id, received_invite.row_id);
    assert_eq!(folder_name, &sent_invite.folder_name);
    assert_eq!(folder_name, &received_invite.folder_name);

    // Name and email should be for the *other* recipient
    assert_eq!("name_two", &sent_invite.recipient_name);
    assert_eq!("name_one", &received_invite.recipient_name);
    assert_eq!(Some("two@example.com"), sent_invite.recipient_email.as_deref());
    assert_eq!(Some("one@example.com"), received_invite.recipient_email.as_deref());

    teardown(TEST_ID).await;

    Ok(())
}
