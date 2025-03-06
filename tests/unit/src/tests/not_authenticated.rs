use anyhow::Result;
use sos_account::{Account, LocalAccount};
use sos_core::{
    commit::CommitHash,
    crypto::{AccessKey, Cipher, KeyDerivation},
    ErrorExt, Paths, VaultId,
};
use sos_net::NetworkAccount;
use sos_password::diceware::generate_passphrase;
use sos_test_utils::{make_client_backend, setup, teardown};

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

    assert_account(&mut account).await?;

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

    assert_account(&mut account).await?;

    teardown(TEST_ID).await;

    Ok(())
}

async fn assert_account(account: &mut impl Account) -> Result<()> {
    let folder_id = VaultId::new_v4();

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
        .identity_folder_summary()
        .await
        .err()
        .unwrap()
        .is_forbidden());
    assert!(account
        .reload_identity_folder()
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

    /*
    assert!(account
        .trusted_devices()
        .await
        .err()
        .unwrap()
        .is_forbidden());
        */

    Ok(())
}
