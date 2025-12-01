use anyhow::Result;
use sos_account::Account;
use sos_backend::BackendTarget;
use sos_database::{
    entity::{RecipientRecord, SharedFolderEntity},
    migrations::migrate_client,
    open_file,
};
use sos_sdk::prelude::*;
use sos_test_utils::{setup, teardown};

/// Test shared folder database entities outside of the
/// context of any networking or public API.
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
