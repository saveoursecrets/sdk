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

use crate::database_entity::{
    create_recipients_and_shared_folder_with_invite_status,
    prepare_local_db_account, FOLDER_NAME,
};

/// Test deleting a shared folder when the account identifer
/// is the owner.
///
/// The shared folder should be deleted for both the owner and
/// the participant.
#[tokio::test]
async fn db_entity_shared_folder_delete_owner() -> Result<()> {
    const TEST_ID: &str = "db_entity_shared_folder_delete_owner";
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

    let ((from_account_id, _), (to_account_id, _), folder_id) =
        create_recipients_and_shared_folder_with_invite_status(
            &mut server,
            &mut account1,
            &mut account2,
            Some(InviteStatus::Accepted),
        )
        .await?;

    SharedFolderEntity::delete_shared_folder(
        &server,
        &from_account_id,
        &folder_id,
    )
    .await?;

    // Receiver no longer sees the shared folder
    let receiver_shared_folder_rows = server
        .conn_mut_and_then(move |conn| {
            let entity = SharedFolderEntity::new(conn);
            Ok::<_, anyhow::Error>(
                entity.list_shared_folders(&to_account_id)?,
            )
        })
        .await?;
    assert!(receiver_shared_folder_rows.is_empty());

    // Owner no longer sees the shared folder
    let owner_shared_folder_rows = server
        .conn_mut_and_then(move |conn| {
            let entity = SharedFolderEntity::new(conn);
            Ok::<_, anyhow::Error>(
                entity.list_shared_folders(&from_account_id)?,
            )
        })
        .await?;
    assert!(owner_shared_folder_rows.is_empty());

    // Check in-memory folders list does not contain the shared folder
    let account1_folders = account1.load_folders().await?;
    assert!(!account1_folders.iter().any(|s| s.name() == FOLDER_NAME));

    // Check in-memory folders list does not contain the shared folder
    let account2_folders = account2.load_folders().await?;
    assert!(!account2_folders.iter().any(|s| s.name() == FOLDER_NAME));

    teardown(TEST_ID).await;

    Ok(())
}

/// Test deleting a shared folder when the account identifer
/// is a participant.
///
/// The shared folder should be deleted for the participant but
/// not for the owner.
#[tokio::test]
async fn db_entity_shared_folder_delete_participant() -> Result<()> {
    const TEST_ID: &str = "db_entity_shared_folder_delete_participant";
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

    let ((from_account_id, _), (to_account_id, _), folder_id) =
        create_recipients_and_shared_folder_with_invite_status(
            &mut server,
            &mut account1,
            &mut account2,
            Some(InviteStatus::Accepted),
        )
        .await?;

    SharedFolderEntity::delete_shared_folder(
        &server,
        &to_account_id,
        &folder_id,
    )
    .await?;

    // Receiver no longer sees the shared folder
    let receiver_shared_folder_rows = server
        .conn_mut_and_then(move |conn| {
            let entity = SharedFolderEntity::new(conn);
            Ok::<_, anyhow::Error>(
                entity.list_shared_folders(&to_account_id)?,
            )
        })
        .await?;
    assert!(receiver_shared_folder_rows.is_empty());

    // Owner no longer sees the shared folder
    let owner_shared_folder_rows = server
        .conn_mut_and_then(move |conn| {
            let entity = SharedFolderEntity::new(conn);
            Ok::<_, anyhow::Error>(
                entity.list_shared_folders(&from_account_id)?,
            )
        })
        .await?;
    assert_eq!(1, owner_shared_folder_rows.len());

    // Check in-memory folders list contains the shared folder
    let account1_folders = account1.load_folders().await?;
    assert!(account1_folders.iter().any(|s| s.name() == FOLDER_NAME));

    // Check in-memory folders list does not contain the shared folder
    let account2_folders = account2.load_folders().await?;
    assert!(!account2_folders.iter().any(|s| s.name() == FOLDER_NAME));

    teardown(TEST_ID).await;

    Ok(())
}
