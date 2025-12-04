use anyhow::Result;
use secrecy::SecretString;
use sos_account::Account;
use sos_backend::BackendTarget;
use sos_database::async_sqlite::Client;
use sos_database::entity::InviteStatus;
use sos_database::{
    entity::{AccountRecord, SharedFolderEntity},
    migrations::migrate_client,
    open_file,
};
use sos_net::NetworkAccount;
use sos_sdk::prelude::*;
use sos_test_utils::{default_server_paths, setup, teardown, TestDirs};
use sos_vault::SharedAccess;

use crate::database_entity::{
    create_recipients_and_shared_folder_with_invite_status,
    prepare_local_db_account, FOLDER_NAME,
};

/// Test sending a folder invite to another recipient and
/// the recipient accepts the invite.
#[tokio::test]
async fn db_entity_shared_folder_accept_invite() -> Result<()> {
    const TEST_ID: &str = "db_entity_shared_folder_accept_invite";
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
        prepare_local_db_account(&target, &name).await
    }

    let (_, mut account1, _, _) =
        prepare_db(&dirs, 0, server.clone()).await?;
    let (_, mut account2, _, _) =
        prepare_db(&dirs, 1, server.clone()).await?;

    let ((from_account_id, _), (to_account_id, _), _) =
        create_recipients_and_shared_folder_with_invite_status(
            &mut server,
            &mut account1,
            &mut account2,
            Some(InviteStatus::Accepted),
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
    let account1_folders = account1.load_folders().await?;
    assert!(account1_folders.iter().any(|s| s.name() == FOLDER_NAME));

    // Check in-memory folders list contains the shared folder
    let account2_folders = account2.load_folders().await?;
    assert!(account2_folders.iter().any(|s| s.name() == FOLDER_NAME));

    teardown(TEST_ID).await;

    Ok(())
}

/// Test sending a folder invite to another recipient and
/// the recipient declines the invite.
#[tokio::test]
async fn db_entity_shared_folder_decline_invite() -> Result<()> {
    const TEST_ID: &str = "db_entity_shared_folder_decline_invite";
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
        prepare_local_db_account(&target, &name).await
    }

    let (_, mut account1, _, _) =
        prepare_db(&dirs, 0, server.clone()).await?;
    let (_, mut account2, _, _) =
        prepare_db(&dirs, 1, server.clone()).await?;

    let ((from_account_id, _), (to_account_id, _), _) =
        create_recipients_and_shared_folder_with_invite_status(
            &mut server,
            &mut account1,
            &mut account2,
            Some(InviteStatus::Declined),
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

    // But we should not see any rows as the invite was declined
    assert!(shared_folder_rows.is_empty());

    teardown(TEST_ID).await;

    Ok(())
}
