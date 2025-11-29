use anyhow::Result;
use secrecy::ExposeSecret;
use sos_account::{Account, SecretChange};
use sos_client_storage::NewFolderOptions;
use sos_sdk::prelude::*;
use sos_test_utils::{mock, simulate_device, spawn, teardown};

/// Tests creating a shared folder and having the owner
/// perform basic secret lifecycle operations.
#[tokio::test]
async fn shared_folder_secret_lifecycle() -> Result<()> {
    const TEST_ID: &str = "shared_folder_secret_lifecycle";
    // sos_test_utils::init_tracing();

    // Spawn a backend server and wait for it to be listening
    let server = spawn(TEST_ID, None, None).await?;

    // Prepare mock device
    let mut device = simulate_device(TEST_ID, 1, Some(&server)).await?;
    let password = device.password.clone();

    let folder_name = "shared_folder";
    let options = NewFolderOptions::new(folder_name.to_string());
    device.owner.create_shared_folder(options).await?;

    let folders = device.owner.list_folders().await?;
    let shared_folder =
        folders.iter().find(|f| f.name() == folder_name).unwrap();

    let (meta, secret) = mock::note(TEST_ID, TEST_ID);
    let SecretChange { id: secret_id, .. } = device
        .owner
        .create_secret(meta, secret, shared_folder.id().into())
        .await?;

    let (row, _) = device
        .owner
        .read_secret(&secret_id, Some(shared_folder.id()))
        .await?;

    assert!(matches!(row.secret(), Secret::Note { .. }));

    let new_value = "<new value>";
    let (_, meta, _) = row.into();
    device
        .owner
        .update_secret(
            &secret_id,
            meta,
            Some(Secret::Note {
                text: new_value.into(),
                user_data: Default::default(),
            }),
            shared_folder.id().into(),
        )
        .await?;

    // Sign out and then re-authenticate to check
    // shared folder access from sign in

    device.owner.sign_out().await?;

    let key: AccessKey = password.into();
    device.owner.sign_in(&key).await?;

    // Check we can read a secret created in the previous session
    let (row, _) = device
        .owner
        .read_secret(&secret_id, Some(shared_folder.id()))
        .await?;
    let value = if let Secret::Note { text, .. } = row.secret() {
        text.expose_secret().to_owned()
    } else {
        panic!("expecting a secret note");
    };
    assert_eq!(new_value, &value);

    // Create another secret
    let (meta, secret) = mock::note(TEST_ID, TEST_ID);
    let SecretChange { id: secret_id, .. } = device
        .owner
        .create_secret(meta, secret, shared_folder.id().into())
        .await?;

    // Check secret deletion
    device
        .owner
        .delete_secret(&secret_id, shared_folder.id().into())
        .await?;

    device.owner.sign_out().await?;

    teardown(TEST_ID).await;

    Ok(())
}
