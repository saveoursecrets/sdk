//! Test for running an account integrity report.
use anyhow::Result;
use sos_backend::BackendTarget;

use crate::test_utils::{mock::files::create_file_secret, setup, teardown};
use sos_account::{Account, LocalAccount};
use sos_integrity::{
    account_integrity, FolderIntegrityEvent, IntegrityFailure,
};
use sos_sdk::prelude::*;
use sos_test_utils::make_client_backend;

/// Tests an ok account integrity report.
#[tokio::test]
async fn account_integrity_ok() -> Result<()> {
    const TEST_ID: &str = "account_integrity_ok";
    //crate::test_utils::init_tracing();

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

    let target = target.with_account_id(account.account_id());
    let folders = account.list_folders().await?;
    let total_folders = folders.len();
    let (mut receiver, _) =
        account_integrity(&target, account.account_id(), folders, 1).await?;
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

    let folders = account.list_folders().await?;
    let target = target.with_account_id(account.account_id());

    // Mock a vault removed outside of the app
    remove_folder_vault_externally(&target, default_folder.id()).await?;

    let (mut receiver, _) =
        account_integrity(&target, account.account_id(), folders, 1).await?;
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
    assert!(matches!(failures.remove(0), IntegrityFailure::MissingVault));

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

    let folders = account.list_folders().await?;
    let target = target.with_account_id(account.account_id());

    // Flip some bits to trigger the checksum mismatch
    flip_bits_on_byte(&target, default_folder.id(), true, -8)?;

    let (mut receiver, _) =
        account_integrity(&target, account.account_id(), folders, 1).await?;
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

    let folders = account.list_folders().await?;
    let target = target.with_account_id(account.account_id());
    // Flip some bits to trigger the checksum mismatch
    flip_bits_on_byte(&target, default_folder.id(), false, -8)?;

    let (mut receiver, _) =
        account_integrity(&target, account.account_id(), folders, 1).await?;
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

    let folders = account.list_folders().await?;
    let (mut receiver, cancel_tx) =
        account_integrity(&target, account.account_id(), folders, 1).await?;
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

// Mock removing a vault file outside of the app.
async fn remove_folder_vault_externally(
    target: &BackendTarget,
    folder_id: &VaultId,
) -> Result<()> {
    match target {
        BackendTarget::FileSystem(paths) => {
            let file_location = paths.vault_path(folder_id);
            // Delete the file to trigger the report failure
            std::fs::remove_file(&file_location)?;
        }
        _ => todo!(),
    }
    Ok(())
}

/// Flip bits on a byte in a file seeking to the
/// given offset from the end of the file.
///
/// Used to test for corrupted data.
fn flip_bits_on_byte(
    // file_path: impl AsRef<Path>,
    target: &BackendTarget,
    folder_id: &VaultId,
    vault: bool,
    offset: i64,
) -> Result<()> {
    match target {
        BackendTarget::FileSystem(paths) => {
            let file_path = if vault {
                paths.vault_path(folder_id)
            } else {
                paths.event_log_path(folder_id)
            };

            use std::fs::OpenOptions;
            use std::io::{Read, Seek, SeekFrom, Write};

            // Open the file in read-write mode
            let mut file =
                OpenOptions::new().read(true).write(true).open(&file_path)?;

            file.seek(SeekFrom::End(offset))?;

            // Read the byte
            let mut buffer = [0; 1];
            file.read_exact(&mut buffer)?;

            // Flip all the bits
            buffer[0] ^= 0xFF;

            // Seek back to the byte and write the modified buffer
            file.seek(SeekFrom::End(offset))?;
            file.write_all(&buffer)?;
        }
        _ => todo!("flip_bits for db client backend"),
    }

    Ok(())
}
