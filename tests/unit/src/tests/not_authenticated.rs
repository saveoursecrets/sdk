use anyhow::Result;
use sos_account::{Account, LocalAccount};
use sos_core::{ErrorExt, Paths};
use sos_net::NetworkAccount;
use sos_password::diceware::generate_passphrase;
use sos_test_utils::{make_client_backend, setup, teardown};

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
    assert!(account.account_label().await.err().unwrap().is_forbidden());

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
