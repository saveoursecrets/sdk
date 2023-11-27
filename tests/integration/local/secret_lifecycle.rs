use anyhow::Result;

use std::{io::Cursor, path::PathBuf, sync::Arc};

use sos_net::sdk::{
    account::{AccountsList, FolderStorage, LocalAccount, UserPaths},
    hex,
    passwd::diceware::generate_passphrase,
    vault::{secret::SecretId, Gatekeeper, VaultId},
    vfs,
};

use crate::test_utils::{mock_note, setup, teardown};

const TEST_ID: &str = "secret_lifecycle";

/// Tests the basic secret lifecycle; create, read, update
/// and delete followed by creating a backup.
#[tokio::test]
async fn integration_secret_lifecycle() -> Result<()> {
    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    UserPaths::scaffold(Some(data_dir.clone())).await?;
    let paths = UserPaths::new_global(data_dir.clone());

    let (mut account, new_account) = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    let default_folder = new_account.default_folder();

    account.sign_in(password.clone()).await?;
    let folders = account.list_folders().await?;
    account.open_folder(&default_folder).await?;

    // Create secret
    let (meta, secret) = mock_note("note", TEST_ID);
    let (id, _, _, folder) = account
        .create_secret(meta, secret, Default::default())
        .await?;
    assert_eq!(default_folder, &folder);

    // Read secret
    let (data, _) = account.read_secret(&id, Default::default()).await?;
    assert_eq!(Some(id), data.id);
    assert_eq!("note", data.meta.label());

    // Update secret
    let (meta, secret) = mock_note("note_edited", TEST_ID);
    let (_, _, _, _) = account
        .update_secret(
            &id,
            meta.clone(),
            Some(secret),
            Default::default(),
            None,
        )
        .await?;
    let (data, _) = account.read_secret(&id, Default::default()).await?;
    assert_eq!(meta, data.meta);
    assert_eq!("note_edited", data.meta.label());
    
    // Delete
    account.delete_secret(&id, Default::default()).await?;

    // Export a backup archive
    let archive = data_dir.join("backup.zip");
    account.export_backup_archive(&archive).await?;
    assert!(vfs::try_exists(&archive).await?);

    // Delete the account
    account.delete_account().await?;
    assert!(!account.is_authenticated());

    // Restore from the backup archive.
    let options = RestoreOptions {
        selected: folders.clone(),
        password: Some(password.clone()),
        ..Default::default(),
    };
    LocalAccount::restore_backup_archive(
        Some(&mut account),
        &archive,
        options,
        Some(data_dir.clone()),
    ).await?;

    teardown(TEST_ID).await;

    Ok(())
}
