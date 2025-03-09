use anyhow::Result;
use sos_account::{Account, ClipboardCopyRequest, LocalAccount};
use sos_backend::BackendTarget;
use sos_client_storage::{
    AccessOptions, ClientAccountStorage, ClientBaseStorage,
    ClientDeviceStorage, ClientFolderStorage, ClientSecretStorage,
    ClientStorage, NewFolderOptions,
};
use sos_core::{
    commit::CommitHash,
    crypto::{AccessKey, Cipher, KeyDerivation},
    AccountId, ErrorExt, ExternalFileName, Paths, SecretId, SecretPath,
    VaultFlags, VaultId,
};
use sos_login::{DelegatedAccess, FolderKeys};
use sos_migrate::import::{ImportFormat, ImportTarget};
use sos_net::NetworkAccount;
use sos_password::diceware::generate_passphrase;
use sos_search::QueryFilter;
use sos_test_utils::{
    make_client_backend,
    mock::{self, make_database_account_with_login},
    setup, teardown,
};
use sos_vault::{
    secret::{SecretRow, SecretType},
    Vault,
};
use std::{collections::HashMap, path::PathBuf};

/// Check that API methods on LocalAccount return an
/// AuthenticationError when not authenticated.
#[tokio::test]
async fn not_authenticated_local_account() -> Result<()> {
    const TEST_ID: &str = "not_authenticated_local_account";

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    let paths = Paths::new_client(&data_dir);
    let target = make_client_backend(&paths).await?;

    let (password, _) = generate_passphrase()?;
    let mut account =
        LocalAccount::new_account(TEST_ID.to_string(), password, target)
            .await?;

    assert_account::<<LocalAccount as Account>::Error>(&mut account).await?;

    teardown(TEST_ID).await;

    Ok(())
}

/// Check that API methods on NetworkAccount return an
/// AuthenticationError when not authenticated.
#[tokio::test]
async fn not_authenticated_network_account() -> Result<()> {
    const TEST_ID: &str = "not_authenticated_network_account";

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    let paths = Paths::new_client(&data_dir);
    let target = make_client_backend(&paths).await?;

    let (password, _) = generate_passphrase()?;
    let mut account = NetworkAccount::new_account(
        TEST_ID.to_string(),
        password,
        target,
        Default::default(),
    )
    .await?;

    assert_account::<<NetworkAccount as Account>::Error>(&mut account)
        .await?;

    teardown(TEST_ID).await;

    Ok(())
}

async fn assert_account<E: ErrorExt>(
    account: &mut (impl Account + DelegatedAccess<Error = E>),
) -> Result<()> {
    let folder_id = VaultId::new_v4();
    let secret_id = SecretId::new_v4();

    assert!(!account.is_authenticated().await);
    assert!(account.device_signer().await.err().unwrap().is_forbidden());
    assert!(account
        .new_device_vault()
        .await
        .err()
        .unwrap()
        .is_forbidden());
    assert!(account
        .device_public_key()
        .await
        .err()
        .unwrap()
        .is_forbidden());
    assert!(account.current_device().await.err().unwrap().is_forbidden());
    assert!(account
        .trusted_devices()
        .await
        .err()
        .unwrap()
        .is_forbidden());
    assert!(account
        .public_identity()
        .await
        .err()
        .unwrap()
        .is_forbidden());
    assert!(account.account_name().await.err().unwrap().is_forbidden());

    assert!(account
        .folder_description(&folder_id)
        .await
        .err()
        .unwrap()
        .is_forbidden());
    assert!(account
        .set_folder_description(&folder_id, String::new())
        .await
        .err()
        .unwrap()
        .is_forbidden());
    assert!(account
        .login_folder_summary()
        .await
        .err()
        .unwrap()
        .is_forbidden());
    assert!(account
        .reload_login_folder()
        .await
        .err()
        .unwrap()
        .is_forbidden());

    {
        let (password, _) = generate_passphrase()?;
        let account_key: AccessKey = password.into();
        let cipher = Cipher::AesGcm256;
        let kdf = KeyDerivation::Argon2Id;

        assert!(account
            .change_cipher(&account_key, &cipher, Some(kdf))
            .await
            .err()
            .unwrap()
            .is_forbidden());
    }

    {
        let (password, _) = generate_passphrase()?;
        assert!(account
            .change_account_password(password)
            .await
            .err()
            .unwrap()
            .is_forbidden());
    }

    assert!(account
        .open_folder(&folder_id)
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account.current_folder().await.err().unwrap().is_forbidden());

    assert!(account
        .history(&folder_id)
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .rename_account(String::new())
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .set_account_name(String::new())
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account.delete_account().await.err().unwrap().is_forbidden());
    assert!(account
        .list_secret_ids(&folder_id)
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account.load_folders().await.err().unwrap().is_forbidden());
    assert!(account.list_folders().await.err().unwrap().is_forbidden());
    assert!(account.account_data().await.err().unwrap().is_forbidden());
    assert!(account
        .compact_account()
        .await
        .err()
        .unwrap()
        .is_forbidden());
    assert!(account
        .compact_folder(&folder_id)
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .restore_folder(&folder_id, vec![])
        .await
        .err()
        .unwrap()
        .is_forbidden());

    {
        let (password, _) = generate_passphrase()?;
        let new_key: AccessKey = password.into();
        assert!(account
            .change_folder_password(&folder_id, new_key)
            .await
            .err()
            .unwrap()
            .is_forbidden());
    }

    assert!(account
        .detached_view(&folder_id, CommitHash::default())
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .initialize_search_index()
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account.search_index().await.err().unwrap().is_forbidden());
    assert!(account
        .query_view(&[], None)
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .query_map("", QueryFilter::default())
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account.document_count().await.err().unwrap().is_forbidden());
    assert!(account
        .document_exists(&folder_id, "", None)
        .await
        .err()
        .unwrap()
        .is_forbidden());
    {
        let secret_id = SecretId::new_v4();
        let file_name = ExternalFileName::from([0u8; 32]);
        assert!(account
            .download_file(&folder_id, &secret_id, &file_name)
            .await
            .err()
            .unwrap()
            .is_forbidden());
    }

    {
        let (meta, secret) = mock::note("mock", "mock");
        assert!(account
            .create_secret(meta, secret, AccessOptions::default())
            .await
            .err()
            .unwrap()
            .is_forbidden());
    }

    assert!(account
        .insert_secrets(vec![])
        .await
        .err()
        .unwrap()
        .is_forbidden());

    {
        let (meta, secret) = mock::note("mock", "mock");
        assert!(account
            .update_secret(
                &secret_id,
                meta,
                Some(secret),
                AccessOptions::default()
            )
            .await
            .err()
            .unwrap()
            .is_forbidden());
    }

    assert!(account
        .move_secret(
            &secret_id,
            &folder_id,
            &folder_id,
            AccessOptions::default()
        )
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .move_secret(
            &secret_id,
            &folder_id,
            &folder_id,
            AccessOptions::default()
        )
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .read_secret(&secret_id, None)
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .raw_secret(&folder_id, &secret_id)
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .delete_secret(&secret_id, AccessOptions::default())
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .archive(&folder_id, &secret_id, AccessOptions::default())
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .unarchive(&secret_id, &SecretType::Note, AccessOptions::default())
        .await
        .err()
        .unwrap()
        .is_forbidden());

    {
        let (meta, _) = mock::note("mock", "mock");
        assert!(account
            .update_file(&secret_id, meta, "", AccessOptions::default())
            .await
            .err()
            .unwrap()
            .is_forbidden());
    }

    assert!(account
        .create_folder(NewFolderOptions::new("folder-name".to_string()))
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .rename_folder(&folder_id, "folder-name".to_string())
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .update_folder_flags(&folder_id, VaultFlags::DEFAULT)
        .await
        .err()
        .unwrap()
        .is_forbidden());

    {
        let (password, _) = generate_passphrase()?;
        let key: AccessKey = password.into();
        assert!(account
            .import_folder("", key, false)
            .await
            .err()
            .unwrap()
            .is_forbidden());
    }

    assert!(account
        .import_login_folder(Vault::default())
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .delete_folder(&folder_id)
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .forget_folder(&folder_id)
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .load_avatar(&secret_id, Some(&folder_id))
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .export_contact("", &secret_id, None)
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .export_all_contacts("")
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .import_contacts("", |_| {})
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .export_unsafe_archive("")
        .await
        .err()
        .unwrap()
        .is_forbidden());

    {
        let import_target = ImportTarget {
            format: ImportFormat::OnePasswordCsv,
            path: PathBuf::from(""),
            folder_name: String::new(),
        };
        assert!(account
            .import_file(import_target)
            .await
            .err()
            .unwrap()
            .is_forbidden());
    }

    {
        let clipboard = xclipboard::Clipboard::new()?;
        let target = SecretPath(folder_id, secret_id);
        let request = ClipboardCopyRequest::default();
        assert!(account
            .copy_clipboard(&clipboard, &target, &request)
            .await
            .err()
            .unwrap()
            .is_forbidden());
    }

    assert!(account
        .find_folder_password(&folder_id)
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .remove_folder_password(&folder_id)
        .await
        .err()
        .unwrap()
        .is_forbidden());

    {
        let (password, _) = generate_passphrase()?;
        let key: AccessKey = password.into();
        assert!(account
            .save_folder_password(&folder_id, key)
            .await
            .err()
            .unwrap()
            .is_forbidden());
    }

    Ok(())
}

/// Check that API methods on ClientStorage return an
/// AuthenticationError when not authenticated.
#[tokio::test]
async fn not_authenticated_client_storage() -> Result<()> {
    const TEST_ID: &str = "not_authenticated_client_storage";

    let account_id = AccountId::random();
    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);
    let paths = Paths::new_client(&data_dir).with_account_id(&account_id);
    let mut target = make_client_backend(&paths).await?;
    match &mut target {
        BackendTarget::FileSystem(paths) => {
            Paths::scaffold(&data_dir).await?;
            paths.ensure().await?;
        }
        BackendTarget::Database(paths, client) => {
            paths.ensure_db().await?;
            make_database_account_with_login(client, &account_id).await?;
        }
    }

    let folder_id = VaultId::new_v4();
    let secret_id = SecretId::new_v4();

    let mut account =
        ClientStorage::new_unauthenticated(target, &account_id).await?;

    assert!(!account.is_authenticated());
    assert!(account
        .patch_devices_unchecked(&[])
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .update_vault(&Vault::default(), vec![])
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .remove_folder(&folder_id)
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .import_folder_patches(HashMap::default())
        .await
        .err()
        .unwrap()
        .is_forbidden());

    {
        let (password, _) = generate_passphrase()?;
        let key: AccessKey = password.into();
        assert!(account
            .compact_folder(&folder_id, &key)
            .await
            .err()
            .unwrap()
            .is_forbidden());
    }

    assert!(account
        .rename_folder(&folder_id, "")
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .update_folder_flags(&folder_id, VaultFlags::DEFAULT)
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .description(&folder_id)
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .set_description(&folder_id, "")
        .await
        .err()
        .unwrap()
        .is_forbidden());

    {
        let (meta, secret) = mock::note("mock", "mock");
        let row = SecretRow::new(secret_id, meta, secret);
        assert!(account
            .create_secret(row, AccessOptions::default())
            .await
            .err()
            .unwrap()
            .is_forbidden());
    }

    assert!(account
        .raw_secret(&folder_id, &secret_id)
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .read_secret(&secret_id, &AccessOptions::default())
        .await
        .err()
        .unwrap()
        .is_forbidden());

    {
        let (meta, secret) = mock::note("mock", "mock");
        assert!(account
            .update_secret(
                &secret_id,
                meta,
                Some(secret),
                AccessOptions::default()
            )
            .await
            .err()
            .unwrap()
            .is_forbidden());
    }

    assert!(account
        .delete_secret(&secret_id, AccessOptions::default())
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .remove_secret(&secret_id, &AccessOptions::default())
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .list_secret_ids(&folder_id)
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account.delete_account().await.err().unwrap().is_forbidden());

    {
        let (password, _) = generate_passphrase()?;
        let current_key: AccessKey = password.clone().into();
        let new_key: AccessKey = password.into();
        assert!(account
            .change_password(&Vault::default(), current_key, new_key)
            .await
            .err()
            .unwrap()
            .is_forbidden());
    }

    assert!(account
        .import_login_vault(Vault::default())
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .unlock(&FolderKeys(HashMap::default()))
        .await
        .err()
        .unwrap()
        .is_forbidden());

    {
        let (password, _) = generate_passphrase()?;
        let key: AccessKey = password.into();
        assert!(account
            .unlock_folder(&folder_id, &key)
            .await
            .err()
            .unwrap()
            .is_forbidden());
    }

    assert!(account
        .create_folder(NewFolderOptions::new("folder-name".to_string()))
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .delete_folder(&folder_id, true)
        .await
        .err()
        .unwrap()
        .is_forbidden());

    {
        let (password, _) = generate_passphrase()?;
        let key: AccessKey = password.into();
        assert!(account
            .restore_folder(vec![], &key)
            .await
            .err()
            .unwrap()
            .is_forbidden());
    }

    assert!(account
        .history(&folder_id)
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .initialize_search_index(&FolderKeys(HashMap::default()))
        .await
        .err()
        .unwrap()
        .is_forbidden());

    assert!(account
        .build_search_index(&FolderKeys(HashMap::default()))
        .await
        .err()
        .unwrap()
        .is_forbidden());

    teardown(TEST_ID).await;

    Ok(())
}
