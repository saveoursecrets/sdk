use anyhow::Result;
use secrecy::{ExposeSecret, SecretString};
use sos_account::{Account, SecretChange};
use sos_core::{crypto::AccessKey, VaultId};
use sos_net::NetworkAccount;
use sos_test_utils::mock;
use sos_vault::secret::Secret;

mod shared_folder_secret_lifecycle;
mod shared_folder_write_access;

pub async fn assert_shared_folder_lifecycle(
    owner: &mut NetworkAccount,
    folder_id: &VaultId,
    password: SecretString,
    test_id: &str,
) -> Result<()> {
    let (meta, secret) = mock::note(test_id, test_id);
    let SecretChange { id: secret_id, .. } =
        owner.create_secret(meta, secret, folder_id.into()).await?;

    let (row, _) = owner.read_secret(&secret_id, Some(folder_id)).await?;

    assert!(matches!(row.secret(), Secret::Note { .. }));

    let new_value = "<new value>";
    let (_, meta, _) = row.into();
    owner
        .update_secret(
            &secret_id,
            meta,
            Some(Secret::Note {
                text: new_value.into(),
                user_data: Default::default(),
            }),
            folder_id.into(),
        )
        .await?;

    // Sign out and then re-authenticate to check
    // shared folder access from sign in

    owner.sign_out().await?;

    let key: AccessKey = password.into();
    owner.sign_in(&key).await?;

    // Check we can read a secret created in the previous session
    let (row, _) = owner.read_secret(&secret_id, Some(folder_id)).await?;
    let value = if let Secret::Note { text, .. } = row.secret() {
        text.expose_secret().to_owned()
    } else {
        panic!("expecting a secret note");
    };
    assert_eq!(new_value, &value);

    // Create another secret
    let (meta, secret) = mock::note(test_id, test_id);
    let SecretChange { id: secret_id, .. } =
        owner.create_secret(meta, secret, folder_id.into()).await?;

    // Check secret deletion
    owner.delete_secret(&secret_id, folder_id.into()).await?;

    Ok(())
}
