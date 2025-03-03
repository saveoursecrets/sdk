use anyhow::Result;
use hex;
use sos_client_storage::files::*;
use sos_password::diceware::generate_passphrase;
use sos_vfs as vfs;
use std::path::PathBuf;

#[tokio::test]
async fn file_encrypt_decrypt() -> Result<()> {
    let (passphrase, _) = generate_passphrase()?;
    let input = "../fixtures/sample.heic";
    let output = "target/file-encrypt-decrypt";

    if let Ok(true) = vfs::try_exists(output).await {
        vfs::remove_dir_all(output).await?;
    }

    vfs::create_dir_all(output).await?;

    let encrypted = FileStorage::encrypt_file_passphrase(
        input,
        output,
        passphrase.clone(),
    )
    .await?;

    let target = PathBuf::from(output).join(hex::encode(encrypted.0));
    let decrypted =
        FileStorage::decrypt_file_passphrase(target, &passphrase).await?;

    let contents = vfs::read(input).await?;
    assert_eq!(contents, decrypted);
    Ok(())
}
