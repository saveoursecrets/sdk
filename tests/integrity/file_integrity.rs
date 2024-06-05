//! Test for running a file integrity report.
use anyhow::Result;

use crate::test_utils::{mock::files::create_file_secret, setup, teardown};
use sos_net::sdk::prelude::*;

/// Tests an ok file integrity report.
#[tokio::test]
async fn file_integrity_ok() -> Result<()> {
    const TEST_ID: &str = "file_integrity_ok";

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
    let key: AccessKey = password.into();
    account.sign_in(&key).await?;

    let default_folder = account.default_folder().await.unwrap();

    create_file_secret(&mut account, &default_folder, None).await?;

    let paths = account.paths();
    let files = account.canonical_files().await?;
    let total_files = files.len();
    let (mut receiver, _) = file_integrity_report(paths, files, 1).await?;
    let mut seen_files = 0;

    while let Some(event) = receiver.recv().await {
        match event {
            FileIntegrityEvent::Begin(amount) => {
                assert_eq!(total_files, amount);
            }
            FileIntegrityEvent::OpenFile(_, _) => {
                seen_files += 1;
            }
            FileIntegrityEvent::CloseFile(_) => {
                seen_files -= 1;
            }
            _ => {}
        }
    }

    assert_eq!(0, seen_files);

    account.sign_out().await?;
    teardown(TEST_ID).await;

    Ok(())
}
