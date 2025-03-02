use crate::test_utils::{setup, teardown};
use anyhow::Result;
use sos_account::{Account, LocalAccount, SecretChange};
use sos_backend::BackendTarget;
use sos_core::{crypto::AccessKey, Paths};
use sos_password::diceware::generate_passphrase;
use sos_test_utils::mock;

/// Test exporting a v2 backup archive using the file
/// system backend and then importing it.
#[tokio::test]
async fn backup_export_roundtrip_v2() -> Result<()> {
    const TEST_ID: &str = "backup_export_roundtrip_v2";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    Paths::scaffold(&data_dir).await?;

    let paths = Paths::new_client(&data_dir);
    let target = BackendTarget::FileSystem(paths.clone());

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        target.clone(),
    )
    .await?;

    let key: AccessKey = password.clone().into();
    account.sign_in(&key).await?;
    let default_folder = account.default_folder().await.unwrap();
    let account_id = *account.account_id();

    // Create secret
    let (meta, secret) = mock::note("note", TEST_ID);
    let SecretChange { id, .. } = account
        .create_secret(meta, secret, Default::default())
        .await?;
    let (file_id, _, _, _) =
        mock::files::create_file_secret(&mut account, &default_folder, None)
            .await?;

    let paths = account.paths();
    let archive = paths.documents_dir().join("backup.zip");
    let target = target.with_account_id(account.account_id());
    sos_backend::archive::export_backup_archive(
        &archive,
        &target,
        account.account_id(),
    )
    .await?;

    account.delete_account().await?;

    let accounts =
        LocalAccount::import_backup_archive(&archive, &target).await?;
    assert_eq!(1, accounts.len());

    let mut account =
        LocalAccount::new_unauthenticated(account_id, target.clone()).await?;
    account.sign_in(&key).await?;
    let (note, _) = account.read_secret(&id, Default::default()).await?;
    assert_eq!("note", note.meta().label());

    assert!(account
        .read_secret(&file_id, Default::default())
        .await
        .is_ok());

    let files = target.list_files().await?;
    assert_eq!(1, files.len());

    teardown(TEST_ID).await;

    Ok(())
}
