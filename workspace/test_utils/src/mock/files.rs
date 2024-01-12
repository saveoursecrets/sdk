use crate::mock;
use anyhow::Result;
use sos_net::sdk::prelude::*;
use std::path::PathBuf;
use tokio::sync::mpsc;

pub async fn create_file_secret(
    account: &mut LocalAccount,
    default_folder: &Summary,
    progress_tx: Option<mpsc::Sender<FileProgress>>,
) -> Result<(SecretId, SecretRow, PathBuf)> {
    let (meta, secret, file_path) = mock::file_image_secret()?;

    // Create the file secret in the default folder
    let options = AccessOptions {
        folder: Some(default_folder.clone()),
        file_progress: progress_tx,
    };
    let (id, _, _, _) = account.create_secret(meta, secret, options).await?;
    let (secret_data, _) = account
        .read_secret(&id, Some(default_folder.clone()))
        .await?;

    Ok((id, secret_data, file_path))
}

pub async fn update_file_secret(
    account: &mut LocalAccount,
    default_folder: &Summary,
    secret_data: &SecretRow,
    destination: Option<&Summary>,
    progress_tx: Option<mpsc::Sender<FileProgress>>,
) -> Result<SecretRow> {
    let id = *secret_data.id();

    let mut new_meta = secret_data.meta().clone();
    new_meta.set_label("Text file".to_string());

    let (new_id, _, _, _) = account
        .update_file(
            &id,
            new_meta,
            "tests/fixtures/test-file.txt",
            AccessOptions {
                folder: None,
                file_progress: progress_tx,
            },
            destination,
        )
        .await?;

    let folder = destination
        .cloned()
        .unwrap_or_else(|| default_folder.clone());
    let (new_secret_data, _) =
        account.read_secret(&new_id, Some(folder)).await?;

    Ok(new_secret_data)
}
