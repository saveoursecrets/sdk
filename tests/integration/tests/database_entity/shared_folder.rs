use anyhow::Result;
use secrecy::SecretString;
use sos_account::{Account, FolderCreate};
use sos_backend::BackendTarget;
use sos_client_storage::NewFolderOptions;
use sos_core::{AccountId, Origin, Recipient};
use sos_database::async_sqlite::Client;
use sos_database::entity::InviteStatus;
use sos_database::{
    entity::{
        AccountRecord, RecipientEntity, RecipientRecord, SharedFolderEntity,
    },
    migrations::migrate_client,
    open_file,
};
use sos_net::NetworkAccount;
use sos_sdk::prelude::*;
use sos_test_utils::{default_server_paths, setup, teardown, TestDirs};
use sos_vault::SharedAccess;

const FOLDER_NAME: &str = "shared_folder";

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

/// Test sending a folder invite to another recipient and
/// the recipient accepts the invite.
#[tokio::test]
async fn database_entity_send_folder_invite_accept() -> Result<()> {
    const TEST_ID: &str = "database_entity_send_folder_invite_accept";
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
    ) -> Result<(AccountRecord, NetworkAccount, Summary, SecretString)> {
        let name = format!("{}_account_{}", TEST_ID, index);
        let paths = Paths::new_client(dirs.clients.get(index).unwrap());
        let target = BackendTarget::Database(paths, server);
        super::prepare_local_db_account(&target, &name).await
    }

    let (_, mut account1, _, _) =
        prepare_db(&dirs, 0, server.clone()).await?;
    let (_, mut account2, _, _) =
        prepare_db(&dirs, 1, server.clone()).await?;

    let ((from_account_id, _), (to_account_id, _)) = run_invite_flow(
        &mut server,
        &mut account1,
        &mut account2,
        InviteStatus::Accepted,
    )
    .await?;

    // Sender can see the accepted invite
    let sender_accepted_invites = server
        .conn_mut_and_then(move |conn| {
            let mut entity = SharedFolderEntity::new(conn);
            Ok::<_, anyhow::Error>(entity.sent_folder_invites(
                &from_account_id,
                None,
                Some(InviteStatus::Accepted),
            )?)
        })
        .await?;
    assert_eq!(1, sender_accepted_invites.len());

    // Receiver can see the accepted invite
    let receiver_accepted_invites = server
        .conn_mut_and_then(move |conn| {
            let mut entity = SharedFolderEntity::new(conn);
            Ok::<_, anyhow::Error>(entity.received_folder_invites(
                &to_account_id,
                None,
                Some(InviteStatus::Accepted),
            )?)
        })
        .await?;
    assert_eq!(1, receiver_accepted_invites.len());

    // Receiver can list the shared folder
    let shared_folder_rows = server
        .conn_mut_and_then(move |conn| {
            let entity = SharedFolderEntity::new(conn);
            Ok::<_, anyhow::Error>(
                entity.list_shared_folders(&to_account_id)?,
            )
        })
        .await?;

    let mut shared_folder_records =
        SharedFolderEntity::from_rows(shared_folder_rows).await?;
    assert_eq!(1, shared_folder_records.len());
    let record = shared_folder_records.remove(0);
    assert_eq!(FOLDER_NAME, record.folder.summary.name());
    assert!(record.folder.summary.flags().is_shared());
    assert_eq!(Cipher::X25519, *record.folder.summary.cipher());
    assert!(matches!(
        record.folder.shared_access,
        Some(SharedAccess::WriteAccess(_))
    ));

    // Check in-memory folders list contains the shared folder
    // for the owner we don't need to reload the folders
    let account1_folders = account1.list_folders().await?;
    assert!(account1_folders.iter().any(|s| s.name() == FOLDER_NAME));

    // Check in-memory folders list contains the shared folder
    // but for the recipient of the invite we need to call load_folders()
    // to refresh the in-memory folders list
    let account2_folders = account2.load_folders().await?;
    assert!(account2_folders.iter().any(|s| s.name() == FOLDER_NAME));

    teardown(TEST_ID).await;

    Ok(())
}

/// Test sending a folder invite to another recipient and
/// the recipient declines the invite.
#[tokio::test]
async fn database_entity_send_folder_invite_decline() -> Result<()> {
    const TEST_ID: &str = "database_entity_send_folder_invite_decline";
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
    ) -> Result<(AccountRecord, NetworkAccount, Summary, SecretString)> {
        let name = format!("{}_account_{}", TEST_ID, index);
        let paths = Paths::new_client(dirs.clients.get(index).unwrap());
        let target = BackendTarget::Database(paths, server);
        super::prepare_local_db_account(&target, &name).await
    }

    let (_, mut account1, _, _) =
        prepare_db(&dirs, 0, server.clone()).await?;
    let (_, mut account2, _, _) =
        prepare_db(&dirs, 1, server.clone()).await?;

    let ((from_account_id, _), (to_account_id, _)) = run_invite_flow(
        &mut server,
        &mut account1,
        &mut account2,
        InviteStatus::Declined,
    )
    .await?;

    // Sender can see the declined invite
    let sender_declined_invites = server
        .conn_mut_and_then(move |conn| {
            let mut entity = SharedFolderEntity::new(conn);
            Ok::<_, anyhow::Error>(entity.sent_folder_invites(
                &from_account_id,
                None,
                Some(InviteStatus::Declined),
            )?)
        })
        .await?;
    assert_eq!(1, sender_declined_invites.len());

    // Receiver can see the declined invite
    let receiver_declined_invites = server
        .conn_mut_and_then(move |conn| {
            let mut entity = SharedFolderEntity::new(conn);
            Ok::<_, anyhow::Error>(entity.received_folder_invites(
                &to_account_id,
                None,
                Some(InviteStatus::Declined),
            )?)
        })
        .await?;
    assert_eq!(1, receiver_declined_invites.len());

    // Receiver can list shared folders
    let shared_folder_rows = server
        .conn_mut_and_then(move |conn| {
            let entity = SharedFolderEntity::new(conn);
            Ok::<_, anyhow::Error>(
                entity.list_shared_folders(&to_account_id)?,
            )
        })
        .await?;

    // But we should not see any rows as the invite was declined,
    // the join table entry was not created
    assert!(shared_folder_rows.is_empty());

    teardown(TEST_ID).await;

    Ok(())
}

async fn run_invite_flow(
    server: &mut Client,
    account1: &mut NetworkAccount,
    account2: &mut NetworkAccount,
    invite_status: InviteStatus,
) -> Result<((AccountId, String), (AccountId, String))> {
    // Both accounts must have enabled sharing by
    // creating recipient information
    let recipients = {
        let recipients_info = [
            (
                *account1.account_id(),
                "name_one",
                "one@example.com",
                account1.shared_access_public_key().await?,
            ),
            (
                *account2.account_id(),
                "name_two",
                "two@example.com",
                account2.shared_access_public_key().await?,
            ),
        ];

        let recipients = Vec::new();

        // Register each account as a recipient for sharing
        for (account_id, name, email, public_key) in
            recipients_info.into_iter()
        {
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

            recipients.push(Recipient {
                name: name.to_string(),
                email: Some(email.to_string()),
                public_key,
            });
        }
        recipients
    };

    let options = NewFolderOptions::new(FOLDER_NAME.to_string());
    let (vault, _access_key) = account1
        .prepare_shared_folder(options, recipients.as_slice(), None)
        .await?;
    let shared_folder_id = *vault.id();

    SharedFolderEntity::create_shared_folder(
        &server,
        account1.account_id(),
        &vault,
        recipients.as_slice(),
    )
    .await?;

    todo!("create shared folder in entity test spec");

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
    let from_recipient_public_key =
        account1.shared_access_public_key().await?.to_string();

    // Invite the found recipient
    let to_recipient = found_recipients.remove(0);
    let to_recipient_public_key = to_recipient.recipient_public_key.clone();
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
            Ok::<_, anyhow::Error>(entity.sent_folder_invites(
                &from_account_id,
                None,
                None,
            )?)
        })
        .await?;
    assert_eq!(1, sent_invites.len());

    // Check the received invites list for the receiver (account2)
    let mut received_invites = server
        .conn_mut_and_then(move |conn| {
            let mut entity = SharedFolderEntity::new(conn);
            Ok::<_, anyhow::Error>(entity.received_folder_invites(
                &to_account_id,
                None,
                None,
            )?)
        })
        .await?;
    assert_eq!(1, received_invites.len());

    let sent_invite = sent_invites.remove(0);
    let received_invite = received_invites.remove(0);

    assert_eq!(sent_invite.row_id, received_invite.row_id);
    assert_eq!(FOLDER_NAME, &sent_invite.folder_name);
    assert_eq!(FOLDER_NAME, &received_invite.folder_name);

    assert_eq!(&to_recipient_public_key, &sent_invite.recipient_public_key);
    assert_eq!(
        &from_recipient_public_key,
        &received_invite.recipient_public_key
    );

    // Name and email should be for the *other* recipient
    assert_eq!("name_two", &sent_invite.recipient_name);
    assert_eq!("name_one", &received_invite.recipient_name);
    assert_eq!(
        Some("two@example.com"),
        sent_invite.recipient_email.as_deref()
    );
    assert_eq!(
        Some("one@example.com"),
        received_invite.recipient_email.as_deref()
    );

    // Check the sent invites list for the sender (account1) that have been accepted (should be empty now)
    let accepted_invites = server
        .conn_mut_and_then(move |conn| {
            let mut entity = SharedFolderEntity::new(conn);
            Ok::<_, anyhow::Error>(entity.sent_folder_invites(
                &from_account_id,
                None,
                Some(InviteStatus::Accepted),
            )?)
        })
        .await?;
    assert!(accepted_invites.is_empty());

    // Accept or decline the invite (account2)
    let from_public_key = from_recipient_public_key.clone();
    server
        .conn_mut_and_then(move |conn| {
            let mut entity = SharedFolderEntity::new(conn);
            Ok::<_, anyhow::Error>(entity.update_folder_invite(
                &to_account_id,
                &from_public_key,
                invite_status,
            )?)
        })
        .await?;

    Ok((
        (from_account_id, from_recipient_public_key),
        (to_account_id, to_recipient_public_key),
    ))
}
