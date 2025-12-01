use anyhow::Result;
use sos_backend::BackendTarget;
use sos_database::{
    entity::SharedFolderEntity, migrations::migrate_client, open_file,
};
use sos_sdk::prelude::*;
use sos_test_utils::{setup, teardown};

/// Test shared folder database entities outside of the
/// context of any networking or public API.
#[tokio::test]
async fn database_entity_shared_folder() -> Result<()> {
    const TEST_ID: &str = "database_entity_shared_folder";
    // sos_test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    // Configure the db client
    let paths = Paths::new_client(&data_dir);
    let mut client = open_file(paths.database_file()).await?;
    migrate_client(&mut client).await?;
    let target = BackendTarget::Database(paths, client.clone());

    let (account_record, _account, _, _) =
        super::prepare_local_db_account(&target, TEST_ID).await?;

    let account_row_id = account_record.row_id;
    let recipient_name = "Example";
    let recipient_email = "user@example.com";
    let recipient_public_key = "<mock AGE key>";

    SharedFolderEntity::upsert_recipient(
        &client,
        account_row_id,
        recipient_name.to_string(),
        Some(recipient_email.to_string()),
        recipient_public_key.to_string(),
    )
    .await?;

    teardown(TEST_ID).await;

    Ok(())
}
