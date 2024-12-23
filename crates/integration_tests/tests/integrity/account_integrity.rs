//! Test for running an account integrity report.
use anyhow::Result;

use crate::test_utils::{mock::files::create_file_secret, setup, teardown};
use indexmap::IndexSet;
use sos_net::sdk::prelude::*;
use sos_test_utils::flip_bits_on_byte;

/// Tests an ok account integrity report.
#[tokio::test]
async fn account_integrity_ok() -> Result<()> {
    const TEST_ID: &str = "account_integrity_ok";

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
    let folders: IndexSet<_> =
        account.list_folders().await?.into_iter().collect();

    let total_folders = folders.len();
    let (mut receiver, _) = account_integrity(paths, folders, 1).await?;
    let mut seen_folders = 0;

    while let Some(event) = receiver.recv().await {
        match event {
            FolderIntegrityEvent::Begin(amount) => {
                assert_eq!(total_folders, amount);
            }
            FolderIntegrityEvent::OpenFolder(_) => {
                seen_folders += 1;
            }
            FolderIntegrityEvent::CloseFolder(_) => {
                seen_folders -= 1;
            }
            _ => {}
        }
    }

    assert_eq!(0, seen_folders);

    account.sign_out().await?;
    teardown(TEST_ID).await;

    Ok(())
}

/// Tests an account integrity report with a missing file
/// failure.
#[tokio::test]
async fn account_integrity_missing_file() -> Result<()> {
    const TEST_ID: &str = "account_integrity_missing_file";

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
    let file_location = paths.vault_path(default_folder.id());

    // Delete the file to trigger the report failure
    std::fs::remove_file(&file_location)?;

    let folders: IndexSet<_> =
        account.list_folders().await?.into_iter().collect();
    let (mut receiver, _) = account_integrity(paths, folders, 1).await?;
    let mut failures = Vec::new();

    while let Some(event) = receiver.recv().await {
        match event {
            FolderIntegrityEvent::Failure(_, reason) => {
                failures.push(reason);
            }
            _ => {}
        }
    }
    assert_eq!(1, failures.len());
    assert!(matches!(failures.remove(0), IntegrityFailure::Missing(_)));

    account.sign_out().await?;
    teardown(TEST_ID).await;

    Ok(())
}

/// Tests an account integrity report with a
/// checksum mismatch (corrupted vault).
#[tokio::test]
async fn account_integrity_corrupted_vault() -> Result<()> {
    const TEST_ID: &str = "account_integrity_corrupted_vault";

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
    let file_location = paths.vault_path(default_folder.id());

    // Flip some bits to trigger the checksum mismatch
    flip_bits_on_byte(&file_location, -8)?;

    let folders: IndexSet<_> =
        account.list_folders().await?.into_iter().collect();
    let (mut receiver, _) = account_integrity(paths, folders, 1).await?;
    let mut failures = Vec::new();

    while let Some(event) = receiver.recv().await {
        match event {
            FolderIntegrityEvent::Failure(_, reason) => {
                failures.push(reason);
            }
            _ => {}
        }
    }

    assert_eq!(1, failures.len());
    assert!(matches!(
        failures.remove(0),
        IntegrityFailure::Corrupted { .. }
    ));

    account.sign_out().await?;
    teardown(TEST_ID).await;

    Ok(())
}

/// Tests an account integrity report with a
/// checksum mismatch (corrupted event log).
#[tokio::test]
async fn account_integrity_corrupted_event() -> Result<()> {
    const TEST_ID: &str = "account_integrity_corrupted_event";

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
    let file_location = paths.event_log_path(default_folder.id());

    // Flip some bits to trigger the checksum mismatch
    flip_bits_on_byte(&file_location, -8)?;

    let folders: IndexSet<_> =
        account.list_folders().await?.into_iter().collect();
    let (mut receiver, _) = account_integrity(paths, folders, 1).await?;
    let mut failures = Vec::new();

    while let Some(event) = receiver.recv().await {
        match event {
            FolderIntegrityEvent::Failure(_, reason) => {
                failures.push(reason);
            }
            _ => {}
        }
    }

    assert_eq!(1, failures.len());
    assert!(matches!(
        failures.remove(0),
        IntegrityFailure::Corrupted { .. }
    ));

    account.sign_out().await?;
    teardown(TEST_ID).await;

    Ok(())
}

/// Test canceling an account integrity report.
#[tokio::test]
#[cfg_attr(windows, ignore = "fails with SendError in CI")]
async fn account_integrity_cancel() -> Result<()> {
    const TEST_ID: &str = "account_integrity_cancel";

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
    let folders: IndexSet<_> =
        account.list_folders().await?.into_iter().collect();
    let (mut receiver, cancel_tx) =
        account_integrity(paths, folders, 1).await?;
    let mut canceled = false;

    while let Some(event) = receiver.recv().await {
        match event {
            FolderIntegrityEvent::OpenFolder(_) => {
                canceled = true;
                // The process may have already completed
                // and the cancel receiver may have already
                // been dropped which would cause the send()
                // to fail
                let _ = cancel_tx.send(());
            }
            _ => {}
        }
    }

    assert!(canceled);

    account.sign_out().await?;
    teardown(TEST_ID).await;

    Ok(())
}
