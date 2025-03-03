mod export_roundtrip;
mod export_roundtrip_v2;
mod export_roundtrip_v3;

mod import_v1;
mod import_v2;

mod upgrade_import;

use anyhow::Result;
use secrecy::SecretString;
use sos_account::{Account, LocalAccount, SecretChange};
use sos_backend::BackendTarget;
use sos_core::crypto::AccessKey;
use sos_test_utils::mock;

pub async fn assert_roundtrip(
    account_name: String,
    password: SecretString,
    target: BackendTarget,
) -> Result<()> {
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
    let (meta, secret) = mock::note("note", &account_name);
    let SecretChange { id, .. } = account
        .create_secret(meta, secret, Default::default())
        .await?;

    // Create external file secret
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

    // All files should be deleted after deleting the account
    let files = target.list_files().await?;
    assert_eq!(0, files.len());

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

    Ok(())
}
