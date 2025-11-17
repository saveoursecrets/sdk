//! Test for running a file integrity report.
use anyhow::Result;
use sos_test_utils::make_client_backend;

use sos_account::{Account, LocalAccount};
use sos_integrity::{file_integrity, FileIntegrityEvent, IntegrityFailure};
use sos_sdk::prelude::*;
use sos_sync::StorageEventLogs;
use sos_test_utils::{mock::files::create_file_secret, setup, teardown};

/// Tests an ok file integrity report.
#[tokio::test]
async fn file_integrity_ok() -> Result<()> {
    const TEST_ID: &str = "file_integrity_ok";
    //sos_test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    let paths = Paths::new_client(&data_dir);
    let target = make_client_backend(&paths).await?;

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        target.clone(),
    )
    .await?;
    let key: AccessKey = password.into();
    account.sign_in(&key).await?;

    let default_folder = account.default_folder().await.unwrap();

    create_file_secret(&mut account, &default_folder, None).await?;

    let files = account.canonical_files().await?;
    let total_files = files.len();
    let target = target.with_account_id(account.account_id());
    let (mut receiver, _) = file_integrity(&target, files, 1).await?;
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

/// Tests a file integrity report with a missing file
/// failure.
#[tokio::test]
async fn file_integrity_missing_file() -> Result<()> {
    const TEST_ID: &str = "file_integrity_missing_file";
    //sos_test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    let paths = Paths::new_client(&data_dir);
    let target = make_client_backend(&paths).await?;

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        target.clone(),
    )
    .await?;
    let key: AccessKey = password.into();
    account.sign_in(&key).await?;

    let default_folder = account.default_folder().await.unwrap();

    let (secret_id, _, _, file_name) =
        create_file_secret(&mut account, &default_folder, None).await?;

    let paths = account.paths();
    let file_location = paths.into_file_path_parts(
        default_folder.id(),
        &secret_id,
        &file_name,
    );

    // Delete the file to trigger the report failure
    std::fs::remove_file(&file_location)?;

    let files = account.canonical_files().await?;
    let target = target.with_account_id(account.account_id());
    let (mut receiver, _) = file_integrity(&target, files, 1).await?;
    let mut failures = Vec::new();

    while let Some(event) = receiver.recv().await {
        if let FileIntegrityEvent::Failure(_, reason) = event {
            failures.push(reason);
        }
    }
    assert_eq!(1, failures.len());
    assert!(matches!(
        failures.remove(0),
        IntegrityFailure::MissingFile(_)
    ));

    account.sign_out().await?;
    teardown(TEST_ID).await;

    Ok(())
}

/// Tests a file integrity report with a checksum mismatch (corrupted).
#[tokio::test]
async fn file_integrity_corrupted() -> Result<()> {
    const TEST_ID: &str = "file_integrity_corrupted";
    //sos_test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    let paths = Paths::new_client(&data_dir);
    let target = make_client_backend(&paths).await?;

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        target.clone(),
    )
    .await?;
    let key: AccessKey = password.into();
    account.sign_in(&key).await?;

    let default_folder = account.default_folder().await.unwrap();

    let (secret_id, _, _, file_name) =
        create_file_secret(&mut account, &default_folder, None).await?;

    let paths = account.paths();
    let file_location = paths.into_file_path_parts(
        default_folder.id(),
        &secret_id,
        &file_name,
    );

    // Write different file content to trigger the checksum mismatch
    std::fs::write(&file_location, "corrupted-file-contents".as_bytes())?;

    let files = account.canonical_files().await?;
    let target = target.with_account_id(account.account_id());
    let (mut receiver, _) = file_integrity(&target, files, 1).await?;
    let mut failures = Vec::new();

    while let Some(event) = receiver.recv().await {
        if let FileIntegrityEvent::Failure(_, reason) = event {
            failures.push(reason);
        }
    }
    assert_eq!(1, failures.len());
    assert!(matches!(
        failures.remove(0),
        IntegrityFailure::CorruptedFile { .. }
    ));

    account.sign_out().await?;
    teardown(TEST_ID).await;

    Ok(())
}

/// Test canceling a file integrity report.
#[tokio::test]
#[cfg_attr(windows, ignore = "fails with SendError in CI")]
async fn file_integrity_cancel() -> Result<()> {
    const TEST_ID: &str = "file_integrity_cancel";
    //sos_test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    let paths = Paths::new_client(&data_dir);
    let target = make_client_backend(&paths).await?;

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        target.clone(),
    )
    .await?;
    let key: AccessKey = password.into();
    account.sign_in(&key).await?;

    let default_folder = account.default_folder().await.unwrap();

    create_file_secret(&mut account, &default_folder, None).await?;

    let files = account.canonical_files().await?;
    let target = target.with_account_id(account.account_id());
    let (mut receiver, cancel_tx) = file_integrity(&target, files, 1).await?;
    let mut canceled = false;

    while let Some(event) = receiver.recv().await {
        if let FileIntegrityEvent::OpenFile(_, _) = event {
            canceled = true;
            let _ = cancel_tx.send(true);
            break;
        }
    }

    assert!(canceled);

    account.sign_out().await?;
    teardown(TEST_ID).await;

    Ok(())
}
