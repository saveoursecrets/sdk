use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::sdk::{hex, prelude::*, vfs};

/// Tests creating a file and updating the secret contents.
#[tokio::test]
async fn local_update_file() -> Result<()> {
    const TEST_ID: &str = "update_file";
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    let mut account = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
    )
    .await?;

    let key: AccessKey = password.clone().into();
    account.sign_in(&key).await?;
    let default_folder = account.default_folder().await.unwrap();

    // Create the file secret
    let (meta, secret, _) = mock::file_image_secret()?;
    let SecretChange { id, .. } = account
        .create_secret(meta.clone(), secret, Default::default())
        .await?;

    let new_path = "tests/fixtures/test-file.txt";
    account
        .update_file(&id, meta, new_path, Default::default(), None)
        .await?;

    let (secret_data, _) = account.read_secret(&id, None).await?;

    if let Secret::File {
        content: FileContent::External { checksum, .. },
        ..
    } = secret_data.secret()
    {
        let file_name = hex::encode(checksum);
        let file_content = account
            .download_file(default_folder.id(), &id, &file_name)
            .await?;
        let expected = vfs::read(new_path).await?;
        assert_eq!(expected, file_content);
    } else {
        panic!("unexpected secret type");
    };

    teardown(TEST_ID).await;

    Ok(())
}
