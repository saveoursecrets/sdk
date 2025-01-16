use anyhow::Result;
use secrecy::SecretString;
use sos_backend::AccessPoint;
use sos_core::SecretId;
use sos_core::{
    constants::DEFAULT_VAULT_NAME, crypto::AccessKey, events::WriteEvent,
};
use sos_vault::{
    secret::{Secret, SecretMeta, SecretRow},
    BuilderCredentials, SecretAccess, VaultBuilder,
};

#[tokio::test]
async fn access_point_secret_note() -> Result<()> {
    let passphrase: SecretString = "mock-passphrase".to_owned().into();
    let name = String::from(DEFAULT_VAULT_NAME);
    let description = String::from("Mock Vault Description");

    let vault = VaultBuilder::new()
        .public_name(name)
        .description(description.clone())
        .build(BuilderCredentials::Password(passphrase.clone(), None))
        .await?;

    let mut keeper = AccessPoint::new_vault(vault);
    let key: AccessKey = passphrase.into();
    keeper.unlock(&key).await?;

    //// Decrypt the initialized meta data.
    let meta = keeper.vault_meta().await?;

    assert_eq!(&description, meta.description());

    let secret_label = "Mock Secret".to_string();
    let secret_value = "Super Secret Note".to_string();
    let secret = Secret::Note {
        text: secret_value.into(),
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(secret_label, secret.kind());

    let secret_data = SecretRow::new(
        SecretId::new_v4(),
        secret_meta.clone(),
        secret.clone(),
    );
    let event = keeper.create_secret(&secret_data).await?;
    if let WriteEvent::CreateSecret(secret_uuid, _) = event {
        let (saved_secret_meta, saved_secret, _) =
            keeper.read_secret(&secret_uuid).await?.unwrap();
        assert_eq!(secret, saved_secret);
        assert_eq!(secret_meta, saved_secret_meta);
    } else {
        panic!("test create secret got wrong payload variant");
    }

    keeper.lock();

    Ok(())
}

#[tokio::test]
async fn access_point_secret_account() -> Result<()> {
    let passphrase: SecretString = "mock-passphrase".to_owned().into();
    let name = String::from(DEFAULT_VAULT_NAME);
    let description = String::from("Mock Vault Description");

    let vault = VaultBuilder::new()
        .public_name(name)
        .description(description.clone())
        .build(BuilderCredentials::Password(passphrase.clone(), None))
        .await?;

    let mut keeper = AccessPoint::new_vault(vault);
    let key: AccessKey = passphrase.into();
    keeper.unlock(&key).await?;

    //// Decrypt the initialized meta data.
    let meta = keeper.vault_meta().await?;

    assert_eq!(&description, meta.description());

    let secret_label = "Mock Account Secret".to_string();
    let secret_value = "super-secret-password".to_string();
    let secret = Secret::Account {
        account: "mock-username".to_string(),
        password: secret_value.into(),
        url: vec!["https://example.com".parse()?],
        user_data: Default::default(),
    };
    let secret_meta = SecretMeta::new(secret_label, secret.kind());

    let id = SecretId::new_v4();
    let secret_data = SecretRow::new(id, secret_meta.clone(), secret.clone());
    let event = keeper.create_secret(&secret_data).await?;

    if let WriteEvent::CreateSecret(secret_uuid, _) = event {
        let (saved_secret_meta, saved_secret, _) =
            keeper.read_secret(&secret_uuid).await?.unwrap();
        assert_eq!(secret, saved_secret);
        assert_eq!(secret_meta, saved_secret_meta);
        secret_uuid
    } else {
        panic!("test create secret got wrong payload variant");
    };

    let new_secret_label = "Mock New Account".to_string();
    let new_secret_value = "new-secret-password".to_string();
    let new_secret = Secret::Account {
        account: "mock-new-username".to_string(),
        password: new_secret_value.into(),
        url: vec!["https://example.com/new".parse()?],
        user_data: Default::default(),
    };
    let new_secret_meta =
        SecretMeta::new(new_secret_label.clone(), new_secret.kind());

    keeper
        .update_secret(&id, new_secret_meta, new_secret)
        .await?;

    keeper.lock();

    Ok(())
}
