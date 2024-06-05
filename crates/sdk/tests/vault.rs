use anyhow::Result;
use secrecy::ExposeSecret;
use sos_sdk::prelude::*;
use sos_test_utils::*;

#[tokio::test]
async fn vault_encode_decode_empty() -> Result<()> {
    let (passphrase, _) = generate_passphrase()?;
    let vault = VaultBuilder::new()
        .build(BuilderCredentials::Password(passphrase, None))
        .await?;

    let buffer = encode(&vault).await?;
    let decoded = decode(&buffer).await?;
    assert_eq!(vault, decoded);
    Ok(())
}

#[tokio::test]
async fn vault_encode_decode_secret_note() -> Result<()> {
    let (encryption_key, _, passphrase) = mock_encryption_key()?;
    let mut vault = VaultBuilder::new()
        .build(BuilderCredentials::Password(passphrase, None))
        .await?;

    let secret_label = "Test note";
    let secret_note = "Super secret note for you to read.";
    let (secret_id, _commit, secret_meta, secret_value, _) = mock_vault_note(
        &mut vault,
        &encryption_key,
        secret_label,
        secret_note,
    )
    .await?;

    let buffer = encode(&vault).await?;

    let decoded: Vault = decode(&buffer).await?;
    assert_eq!(vault, decoded);

    let (row, _) = decoded.read(&secret_id).await?;

    let value = row.unwrap();
    let VaultCommit(_, VaultEntry(row_meta, row_secret)) = value.as_ref();

    let row_meta = vault.decrypt(&encryption_key, row_meta).await?;
    let row_secret = vault.decrypt(&encryption_key, row_secret).await?;

    let row_meta: SecretMeta = decode(&row_meta).await?;
    let row_secret: Secret = decode(&row_secret).await?;

    assert_eq!(secret_meta, row_meta);
    assert_eq!(secret_value, row_secret);

    match &row_secret {
        Secret::Note { text, .. } => {
            assert_eq!(secret_note, text.expose_secret());
        }
        _ => panic!("unexpected secret type"),
    }

    Ok(())
}

#[tokio::test]
async fn vault_shared_folder_writable() -> Result<()> {
    let owner = age::x25519::Identity::generate();
    let other_1 = age::x25519::Identity::generate();

    let mut recipients = Vec::new();
    recipients.push(other_1.to_public());

    let vault = VaultBuilder::new()
        .build(BuilderCredentials::Shared {
            owner: &owner,
            recipients,
            read_only: false,
        })
        .await?;

    // Owner adds a secret
    let mut keeper = Gatekeeper::new(vault);
    let key = AccessKey::Identity(owner.clone());
    keeper.unlock(&key).await?;
    let (meta, secret, _, _) =
        mock_secret_note("Shared label", "Shared note").await?;
    let id = SecretId::new_v4();
    let secret_data = SecretRow::new(id, meta.clone(), secret.clone());
    keeper.create_secret(&secret_data).await?;

    // In the real world this exchange of the vault
    // would happen via a sync operation
    let vault: Vault = keeper.into();

    // Ensure recipient information is encoded properly
    let encoded = encode(&vault).await?;
    let vault: Vault = decode(&encoded).await?;

    let mut keeper_1 = Gatekeeper::new(vault);
    let key = AccessKey::Identity(other_1.clone());
    keeper_1.unlock(&key).await?;
    if let Some((read_meta, read_secret, _)) =
        keeper_1.read_secret(&id).await?
    {
        assert_eq!(meta, read_meta);
        assert_eq!(secret, read_secret);
    } else {
        unreachable!();
    }

    let (new_meta, new_secret, _, _) =
        mock_secret_note("Shared label updated", "Shared note updated")
            .await?;
    keeper_1
        .update_secret(&id, new_meta.clone(), new_secret.clone())
        .await?;

    // In the real world this exchange of the vault
    // would happen via a sync operation
    let vault: Vault = keeper_1.into();

    // Check the owner can see the updated secret
    let mut keeper = Gatekeeper::new(vault);
    let key = AccessKey::Identity(owner.clone());
    keeper.unlock(&key).await?;
    if let Some((read_meta, read_secret, _)) = keeper.read_secret(&id).await?
    {
        assert_eq!(new_meta, read_meta);
        assert_eq!(new_secret, read_secret);
    } else {
        unreachable!();
    }

    Ok(())
}

#[tokio::test]
async fn vault_shared_folder_readonly() -> Result<()> {
    let owner = age::x25519::Identity::generate();
    let other_1 = age::x25519::Identity::generate();

    let mut recipients = Vec::new();
    recipients.push(other_1.to_public());

    let vault = VaultBuilder::new()
        .build(BuilderCredentials::Shared {
            owner: &owner,
            recipients,
            read_only: true,
        })
        .await?;

    // Owner adds a secret
    let mut keeper = Gatekeeper::new(vault);
    let key = AccessKey::Identity(owner.clone());
    keeper.unlock(&key).await?;
    let (meta, secret, _, _) =
        mock_secret_note("Shared label", "Shared note").await?;
    let id = SecretId::new_v4();
    let secret_data = SecretRow::new(id, meta.clone(), secret.clone());
    keeper.create_secret(&secret_data).await?;

    // Check the owner can update
    let (new_meta, new_secret, _, _) =
        mock_secret_note("Shared label updated", "Shared note updated")
            .await?;
    keeper
        .update_secret(&id, new_meta.clone(), new_secret.clone())
        .await?;

    // In the real world this exchange of the vault
    // would happen via a sync operation
    let vault: Vault = keeper.into();

    // Ensure recipient information is encoded properly
    let encoded = encode(&vault).await?;
    let vault: Vault = decode(&encoded).await?;

    let mut keeper_1 = Gatekeeper::new(vault);
    let key = AccessKey::Identity(other_1.clone());
    keeper_1.unlock(&key).await?;

    // Other recipient can read the secret
    if let Some((read_meta, read_secret, _)) =
        keeper_1.read_secret(&id).await?
    {
        assert_eq!(new_meta, read_meta);
        assert_eq!(new_secret, read_secret);
    } else {
        unreachable!();
    }

    //  If the other recipient tries to update
    //  they get a permission denied error
    let (updated_meta, updated_secret, _, _) = mock_secret_note(
        "Shared label update denied",
        "Shared note update denied",
    )
    .await?;
    let result = keeper_1
        .update_secret(&id, updated_meta.clone(), updated_secret.clone())
        .await;
    assert!(matches!(result, Err(Error::PermissionDenied)));

    // Trying to create a secret is also denied
    let id = SecretId::new_v4();
    let secret_data =
        SecretRow::new(id, updated_meta.clone(), updated_secret.clone());
    let result = keeper_1.create_secret(&secret_data).await;
    assert!(matches!(result, Err(Error::PermissionDenied)));

    // Trying to delete a secret is also denied
    let result = keeper_1.delete_secret(&id).await;
    assert!(matches!(result, Err(Error::PermissionDenied)));

    Ok(())
}
