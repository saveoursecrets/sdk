use crate::test_utils::{mock, setup, teardown};
use anyhow::Result;
use sos_net::sdk::{
    account::{LocalAccount, UserPaths},
    hex,
    passwd::diceware::generate_passphrase,
    vault::secret::{FileContent, Secret},
    vfs,
};

const TEST_ID: &str = "update_file";

/// Tests creating a file and updating the secret contents.
#[tokio::test]
async fn integration_update_file() -> Result<()> {
    //crate::test_utils::init_tracing();

    let mut dirs = setup(TEST_ID, 1).await?;
    let data_dir = dirs.clients.remove(0);

    let account_name = TEST_ID.to_string();
    let (password, _) = generate_passphrase()?;

    UserPaths::scaffold(Some(data_dir.clone())).await?;
    UserPaths::new_global(data_dir.clone());

    let (mut account, new_account) = LocalAccount::new_account(
        account_name.clone(),
        password.clone(),
        Some(data_dir.clone()),
        None,
    )
    .await?;

    let default_folder = new_account.default_folder();
    account.sign_in(password.clone()).await?;
    account.open_folder(&default_folder).await?;

    // Create the file secret
    let (meta, secret, _) = mock::file_image_secret()?;
    let (id, _, _, _) = account
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
