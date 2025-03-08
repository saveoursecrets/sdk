use anyhow::Result;
use sos_backend::AccessPoint;
use sos_core::{crypto::AccessKey, SecretId};
use sos_test_utils::*;
use sos_vault::{
    secret::SecretRow, BuilderCredentials, ChangePassword, SecretAccess,
    VaultBuilder,
};

#[tokio::test]
async fn change_password() -> Result<()> {
    let (_, _, current_key) = mock::encryption_key()?;
    let mock_vault = VaultBuilder::new()
        .build(BuilderCredentials::Password(current_key.clone(), None))
        .await?;

    let mut keeper = AccessPoint::from_vault(mock_vault);
    let key: AccessKey = current_key.clone().into();
    keeper.unlock(&key).await?;

    // Propagate some secrets
    let notes = vec![
        ("label1", "note1"),
        ("label2", "note2"),
        ("label3", "note3"),
    ];
    for item in notes {
        let (secret_meta, secret_value, _, _) =
            mock::secret_note(item.0, item.1).await?;
        let secret_data =
            SecretRow::new(SecretId::new_v4(), secret_meta, secret_value);
        keeper.create_secret(&secret_data).await?;
    }

    let expected_len = keeper.vault().len();
    assert_eq!(3, expected_len);

    let (_, _, new_key) = mock::encryption_key()?;

    let expected_passphrase = AccessKey::Password(new_key.clone());

    // Using an incorrect current passphrase should fail
    let bad_passphrase = AccessKey::Password(String::from("oops").into());
    assert!(ChangePassword::new(
        keeper.vault(),
        bad_passphrase,
        AccessKey::Password(new_key.clone()),
        None,
    )
    .build()
    .await
    .is_err());

    // Using a valid current passphrase should succeed
    let (new_key, from_vault, event_log_events) = ChangePassword::new(
        keeper.vault(),
        AccessKey::Password(current_key),
        AccessKey::Password(new_key),
        None,
    )
    .build()
    .await?;

    assert_eq!(expected_passphrase, new_key);
    assert_eq!(expected_len, from_vault.len());
    assert_eq!(expected_len + 1, event_log_events.len());

    Ok(())
}
