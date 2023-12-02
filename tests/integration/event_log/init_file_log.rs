use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::{
    events::Patch,
    sdk::{
        account::{
            LocalAccount, UserPaths,
        },
        events::{FileEvent, FileEventLog},
        passwd::diceware::generate_passphrase,
        vault::secret::{IdentityKind, SecretType},
    },
};

const TEST_ID: &str = "init_file_log";

/// Tests lazy initialization of the file events log.
#[tokio::test]
async fn integration_events_init_file_log() -> Result<()> {
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
    
    // Create an external file secret
    let (meta, secret, file_path) = mock::file_image_secret()?;
    account.create_secret(meta, secret, Default::default()).await?;
    
    // Store the file events log so we can delete and re-create
    let file_events = account.paths().file_events();

    let mut event_log = FileEventLog::new_file(&file_events).await?;
    let records = event_log.patch_until(None).await?;
    let patch: Patch = records.into();

    println!("File events: {}", patch.len());
    
    teardown(TEST_ID).await;

    Ok(())
}
