//! Helper functions for mocking files.
use crate::mock;
use anyhow::Result;
use sos_account::{Account, SecretChange};
use sos_client_storage::AccessOptions;
use sos_core::{ExternalFileName, SecretId};
use sos_external_files::FileProgress;
use sos_vault::{
    secret::{FileContent, Secret, SecretRow},
    Summary,
};
use std::path::PathBuf;
use tokio::sync::mpsc;

/// Create a file secret.
pub async fn create_file_secret<E>(
    account: &mut (impl Account<Error = E> + Send + Sync),
    default_folder: &Summary,
    progress_tx: Option<mpsc::Sender<FileProgress>>,
) -> Result<(SecretId, SecretRow, PathBuf, ExternalFileName)>
where
    E: std::error::Error + Send + Sync + 'static,
{
    let (meta, secret, file_path) = mock::file_image_secret()?;

    // Create the file secret in the default folder
    let options = AccessOptions {
        folder: Some(*default_folder.id()),
        file_progress: progress_tx,
        ..Default::default()
    };
    let result = account.create_secret(meta, secret, options).await?;
    let (secret_data, _) = account
        .read_secret(&result.id, Some(default_folder.id()))
        .await?;

    let file_name: ExternalFileName = if let Secret::File {
        content: FileContent::External { checksum, .. },
        ..
    } = secret_data.secret()
    {
        (*checksum).into()
    } else {
        panic!("expecting file secret");
    };

    Ok((result.id, secret_data, file_path, file_name))
}

/// Update a file secret.
pub async fn update_file_secret<E>(
    account: &mut (impl Account<Error = E> + Send + Sync),
    default_folder: &Summary,
    secret_data: &SecretRow,
    destination: Option<&Summary>,
    progress_tx: Option<mpsc::Sender<FileProgress>>,
) -> Result<(SecretRow, ExternalFileName)>
where
    E: std::error::Error + Send + Sync + 'static,
{
    let id = *secret_data.id();

    let mut new_meta = secret_data.meta().clone();
    new_meta.set_label("Text file".to_string());

    let SecretChange { id: new_id, .. } = account
        .update_file(
            &id,
            new_meta,
            "../fixtures/test-file.txt",
            AccessOptions {
                folder: None,
                file_progress: progress_tx,
                destination: destination.map(|f| *f.id()),
            },
        )
        .await?;

    let folder = destination
        .cloned()
        .unwrap_or_else(|| default_folder.clone());
    let (new_secret_data, _) =
        account.read_secret(&new_id, Some(folder.id())).await?;

    let file_name: ExternalFileName = if let Secret::File {
        content: FileContent::External { checksum, .. },
        ..
    } = new_secret_data.secret()
    {
        (*checksum).into()
    } else {
        panic!("expecting file secret");
    };

    Ok((new_secret_data, file_name))
}

/// Create an attachment.
pub async fn create_attachment<E>(
    account: &mut (impl Account<Error = E> + Send + Sync),
    secret_id: &SecretId,
    destination: &Summary,
    progress_tx: Option<mpsc::Sender<FileProgress>>,
) -> Result<(SecretId, SecretRow, ExternalFileName)>
where
    E: std::error::Error + Send + Sync + 'static,
{
    let (mut secret_data, _) = account
        .read_secret(secret_id, Some(destination.id()))
        .await?;
    let (meta, secret, _) = mock::file_text_secret()?;
    let attachment_id = SecretId::new_v4();
    let attachment = SecretRow::new(attachment_id, meta, secret);
    secret_data.secret_mut().add_field(attachment);
    account
        .update_secret(
            secret_id,
            secret_data.meta().clone(),
            Some(secret_data.secret().clone()),
            AccessOptions {
                folder: Some(*destination.id()),
                file_progress: progress_tx,
                ..Default::default()
            },
        )
        .await?;
    let (secret_data, _) = account
        .read_secret(&secret_id, Some(destination.id()))
        .await?;
    let attached = secret_data
        .secret()
        .find_field_by_id(&attachment_id)
        .expect("attachment to exist");
    let file_name: ExternalFileName = if let Secret::File {
        content: FileContent::External { checksum, .. },
        ..
    } = attached.secret()
    {
        (*checksum).into()
    } else {
        panic!("expecting file secret variant (attachment)");
    };

    Ok((attachment_id, secret_data, file_name))
}

/// Update an attachment.
pub async fn update_attachment<E>(
    account: &mut (impl Account<Error = E> + Send + Sync),
    secret_data: &mut SecretRow,
    attachment_id: &SecretId,
    destination: &Summary,
    progress_tx: Option<mpsc::Sender<FileProgress>>,
) -> Result<(SecretRow, SecretRow, ExternalFileName)>
where
    E: std::error::Error + Send + Sync + 'static,
{
    let (meta, secret, _) = mock::file_image_secret()?;
    let new_attachment = SecretRow::new(*attachment_id, meta, secret);
    secret_data.secret_mut().update_field(new_attachment)?;
    account
        .update_secret(
            secret_data.id(),
            secret_data.meta().clone(),
            Some(secret_data.secret().clone()),
            AccessOptions {
                folder: Some(*destination.id()),
                file_progress: progress_tx,
                ..Default::default()
            },
        )
        .await?;

    let (updated_secret_data, _) = account
        .read_secret(secret_data.id(), Some(destination.id()))
        .await?;
    assert_eq!(1, updated_secret_data.secret().user_data().len());

    let updated_attachment = updated_secret_data
        .secret()
        .find_field_by_id(&attachment_id)
        .cloned()
        .expect("attachment to exist");

    let file_name: ExternalFileName = if let Secret::File {
        content: FileContent::External { checksum, .. },
        ..
    } = updated_attachment.secret()
    {
        (*checksum).into()
    } else {
        panic!("expecting file secret variant (attachment)");
    };

    Ok((updated_secret_data, updated_attachment, file_name))
}

/// Delete an attachment.
pub async fn delete_attachment<E>(
    account: &mut (impl Account<Error = E> + Send + Sync),
    mut secret_data: SecretRow,
    attachment_id: &SecretId,
    destination: &Summary,
    progress_tx: Option<mpsc::Sender<FileProgress>>,
) -> Result<()>
where
    E: std::error::Error + Send + Sync + 'static,
{
    secret_data.secret_mut().remove_field(&attachment_id);

    let secret_id = *secret_data.id();
    let (_, meta, secret) = secret_data.into();
    account
        .update_secret(
            &secret_id,
            meta,
            Some(secret),
            AccessOptions {
                folder: Some(*destination.id()),
                file_progress: progress_tx,
                ..Default::default()
            },
        )
        .await?;

    Ok(())
}
