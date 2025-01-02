use anyhow::Result;
use sos_account::archive::*;
use sos_sdk::{encode, identity::IdentityFolder, vault::Vault, Paths};
use std::io::Cursor;

#[tokio::test]
async fn archive_buffer_async() -> Result<()> {
    let mut archive = Vec::new();
    let writer = Writer::new(Cursor::new(&mut archive));
    let dir = tempfile::tempdir()?;

    Paths::scaffold(Some(dir.path().to_owned())).await?;

    let identity_vault = IdentityFolder::new(
        "Mock".to_string(),
        "mock-password".to_string().into(),
        Some(dir.path().to_owned()),
    )
    .await?;
    let address = identity_vault.address().clone();
    let identity_vault: Vault = identity_vault.into();

    let identity = encode(&identity_vault).await?;

    let vault: Vault = Default::default();
    let vault_buffer = encode(&vault).await?;

    let zip = writer
        .set_identity(&address, &identity)
        .await?
        .add_vault(*vault.id(), &vault_buffer)
        .await?
        .finish()
        .await?;

    let expected_vault_entries =
        vec![(vault.summary().clone(), vault_buffer)];

    // Decompress and extract
    let cursor = zip.into_inner();
    let mut reader = Reader::new(Cursor::new(cursor.get_ref())).await?;
    let inventory = reader.inventory().await?;

    assert_eq!(address, inventory.manifest.address);
    assert_eq!("Mock", inventory.identity.name());
    assert_eq!(1, inventory.vaults.len());

    let (manifest_decoded, identity_entry, vault_entries, _, _, _, _, _) =
        reader.prepare().await?.finish().await?;

    assert_eq!(address, manifest_decoded.address);

    let (identity_summary, identity_buffer) = identity_entry;
    assert_eq!(identity_vault.summary(), &identity_summary);
    assert_eq!(identity, identity_buffer);
    assert_eq!(expected_vault_entries, vault_entries);

    Ok(())
}