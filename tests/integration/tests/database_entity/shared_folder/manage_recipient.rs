use anyhow::Result;
use sos_account::Account;
use sos_backend::BackendTarget;
use sos_core::Recipient;
use sos_database::{
    entity::{RecipientRecord, SharedFolderEntity},
    migrations::migrate_client,
    open_file,
};
use sos_sdk::prelude::*;
use sos_test_utils::{setup, teardown};

use crate::database_entity::prepare_local_db_account;

/// Test managing recipient information for an account.
#[tokio::test]
async fn db_entity_shared_folder_manage_recipient() -> Result<()> {
    const TEST_ID: &str = "db_entity_shared_folder_manage_recipient";
    // sos_test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    // Configure the db client
    let paths = Paths::new_client(&data_dir);
    let mut client = open_file(paths.database_file()).await?;
    migrate_client(&mut client).await?;
    let target = BackendTarget::Database(paths, client.clone());

    let (_account_record, account, _, _) =
        prepare_local_db_account(&target, TEST_ID).await?;

    let account_id = *account.account_id();
    let recipient_name = "Example";
    let recipient_email = "user@example.com";
    let recipient_public_key = account.shared_access_public_key().await?;

    let recipient = Recipient {
        name: recipient_name.to_owned(),
        email: Some(recipient_email.to_owned()),
        public_key: recipient_public_key.clone(),
    };

    // Initial insert on creating recipient information
    let recipient_id = client
        .conn_mut_and_then(move |conn| {
            let mut entity = SharedFolderEntity::new(conn);
            let recipient_id =
                entity.upsert_recipient(account_id, recipient)?;
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
    assert_eq!(
        recipient_public_key.to_string(),
        recipient_record.recipient_public_key
    );

    let new_recipient_name = "Example";
    let new_recipient_email = "new-user@example.com";

    let recipient = Recipient {
        name: new_recipient_name.to_owned(),
        email: Some(new_recipient_email.to_owned()),
        public_key: recipient_public_key.clone(),
    };

    // Update recipient information for an account
    let new_recipient_id = client
        .conn_mut_and_then(move |conn| {
            let mut entity = SharedFolderEntity::new(conn);
            let recipient_id =
                entity.upsert_recipient(account_id, recipient)?;
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

    teardown(TEST_ID).await;

    Ok(())
}
