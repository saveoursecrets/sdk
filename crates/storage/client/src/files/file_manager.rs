//! File manager to keep external files in sync
//! as secrets are created, updated and moved.
use crate::{files::FileStorage, Error, Result};
use hex;
use sos_backend::FileEventLog;
use sos_core::events::{EventLog, FileEvent};
use sos_core::{
    basename, ExternalFileName, Paths, SecretId, SecretPath, VaultId,
};
use sos_external_files::{
    EncryptedFile, FileMutationEvent, FileProgress, FileSource,
    FileStorageDiff, FileStorageResult,
};
use sos_vault::{
    secret::{FileContent, Secret, SecretRow, UserData},
    Summary,
};
use sos_vfs as vfs;
use std::{collections::HashMap, path::Path, sync::Arc};
use tokio::sync::{mpsc, RwLock};

/// Manages external files.
pub struct ExternalFileManager {
    paths: Arc<Paths>,
    file_log: Arc<RwLock<FileEventLog>>,
    file_password: secrecy::SecretString,
}

impl ExternalFileManager {
    /// Create new external file manager.
    pub fn new(
        paths: Arc<Paths>,
        file_log: Arc<RwLock<FileEventLog>>,
        file_password: secrecy::SecretString,
    ) -> Self {
        Self {
            paths,
            file_log,
            file_password,
        }
    }

    /// Append file mutation events to the file event log.
    pub async fn append_file_mutation_events(
        &mut self,
        events: &[FileMutationEvent],
    ) -> Result<()> {
        let mut file_events = Vec::new();
        for event in events {
            match event {
                FileMutationEvent::Create { event, .. } => {
                    file_events.push(event.clone())
                }
                FileMutationEvent::Move(event) => {
                    file_events.push(event.clone())
                }
                FileMutationEvent::Delete(event) => {
                    file_events.push(event.clone())
                }
            }
        }

        let mut writer = self.file_log.write().await;
        writer.apply(file_events.as_slice()).await?;

        Ok(())
    }

    /// Encrypt a file and move it to the external file storage location.
    async fn encrypt_file_storage<P: AsRef<Path>>(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        source: P,
    ) -> Result<EncryptedFile> {
        // Encrypt and write to disc
        Ok(FileStorage::encrypt_file_storage(
            self.file_password.clone(),
            source,
            &self.paths,
            vault_id,
            secret_id,
        )
        .await?)
    }

    /// Decrypt a file in the storage location and return the buffer.
    async fn decrypt_file_storage(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &ExternalFileName,
    ) -> Result<Vec<u8>> {
        Ok(FileStorage::decrypt_file_storage(
            &self.file_password,
            &self.paths,
            vault_id,
            secret_id,
            file_name,
        )
        .await?)
    }

    /// Decrypt a file and return the buffer.
    pub async fn download_file(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &ExternalFileName,
    ) -> Result<Vec<u8>> {
        self.decrypt_file_storage(vault_id, secret_id, file_name)
            .await
    }

    /// Remove the directory containing all the files for a folder.
    pub(crate) async fn delete_folder_files(
        &self,
        folder_id: &VaultId,
    ) -> Result<Vec<FileEvent>> {
        use sos_external_files::list_folder_files;
        let mut events = Vec::new();
        let mut folder_files =
            list_folder_files(&self.paths, folder_id).await?;
        for (secret_id, mut external_files) in folder_files.drain(..) {
            for file_name in external_files.drain(..) {
                // Remove each file as we go and create
                // a file deletion event
                let file = self
                    .paths
                    .into_file_path_parts(folder_id, &secret_id, &file_name);
                vfs::remove_file(&file).await?;

                events.push(FileEvent::DeleteFile(
                    SecretPath(*folder_id, secret_id),
                    file_name,
                ));
            }
        }

        // Remove the folder finally
        let folder_files = self.paths.into_file_folder_path(folder_id);
        if vfs::try_exists(&folder_files).await? {
            vfs::remove_dir_all(&folder_files).await?;
        }
        Ok(events)
    }

    /// Create external files when a file secret is created.
    pub(crate) async fn create_files(
        &mut self,
        summary: &Summary,
        secret_data: SecretRow,
        file_progress: &mut Option<mpsc::Sender<FileProgress>>,
    ) -> Result<(Vec<FileMutationEvent>, Option<(SecretId, SecretRow)>)> {
        self.write_update_checksum(summary, secret_data, None, file_progress)
            .await
    }

    /// Update external files when a file secret is updated.
    pub(crate) async fn update_files(
        &mut self,
        old_summary: &Summary,
        new_summary: &Summary,
        old_secret: &SecretRow,
        new_secret: SecretRow,
        file_progress: &mut Option<mpsc::Sender<FileProgress>>,
    ) -> Result<(Vec<FileMutationEvent>, Option<(SecretId, SecretRow)>)> {
        let mut results = Vec::new();

        let old_secret_id = old_secret.id();
        let new_secret_id = new_secret.id();

        let has_moved =
            new_summary != old_summary || new_secret.id() != old_secret.id();

        let diff =
            get_file_secret_diff(old_secret.secret(), new_secret.secret());

        let changed_files = get_file_sources(new_secret.secret());
        let deleted = diff.deleted;
        let unchanged_files = diff.unchanged;

        // Delete any attachments that no longer exist
        if !deleted.is_empty() {
            let deleted = self
                .delete_files(
                    old_summary,
                    old_secret,
                    Some(deleted),
                    file_progress,
                )
                .await?;
            results.extend_from_slice(&deleted);
        }

        // Move unchanged files
        if has_moved {
            let moved = self
                .move_files(
                    &new_secret,
                    old_summary.id(),
                    new_summary.id(),
                    old_secret_id,
                    new_secret_id,
                    Some(unchanged_files),
                    file_progress,
                )
                .await?;
            results.extend_from_slice(&moved);
        }

        // Write changed files to the new location
        let write_update = if !changed_files.is_empty() {
            let (written, write_update) = self
                .write_update_checksum(
                    new_summary,
                    new_secret,
                    Some(changed_files),
                    file_progress,
                )
                .await?;
            results.extend_from_slice(&written);
            write_update
        } else {
            None
        };

        Ok((results, write_update))
    }

    /// Delete a collection of files from the external storage.
    pub(crate) async fn delete_files(
        &self,
        summary: &Summary,
        secret_data: &SecretRow,
        targets: Option<Vec<&Secret>>,
        file_progress: &mut Option<mpsc::Sender<FileProgress>>,
    ) -> Result<Vec<FileMutationEvent>> {
        let mut events = Vec::new();

        let id = secret_data.id();
        let targets = targets.unwrap_or_else(|| {
            get_external_file_secrets(secret_data.secret())
        });

        // Whilst highly unlikely as the files are encrypted and
        // non-deterministic it is possible for multiple files to
        // have the same checksum and attempting to remove multiple
        // files with the same checksum would fail as the first
        // deletion would already have removed the file.
        //
        // However we don't want to treat this as an error condition
        // so remove duplicate checksums before deletion.
        let mut checksums = HashMap::new();
        for target in targets {
            if let Secret::File {
                content: FileContent::External { checksum, name, .. },
                ..
            } = target
            {
                checksums.insert(checksum, name.to_owned());
            }
        }

        for (checksum, name) in checksums {
            if let Some(file_progress) = file_progress.as_mut() {
                let _ =
                    file_progress.send(FileProgress::Delete { name }).await;
            }

            let file_name = ExternalFileName::from(checksum);
            events
                .push(self.delete_file(summary.id(), id, &file_name).await?);
        }
        Ok(events.into_iter().map(FileMutationEvent::Delete).collect())
    }

    /// Delete a file from the storage location.
    pub(crate) async fn delete_file(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &ExternalFileName,
    ) -> Result<FileEvent> {
        let vault_path = self.paths.into_file_folder_path(vault_id);
        let secret_path =
            self.paths.into_file_secret_path(vault_id, secret_id);
        let path = self
            .paths
            .into_file_path_parts(vault_id, secret_id, file_name);

        vfs::remove_file(path).await?;

        // Prune empty directories
        if secret_path.read_dir()?.next().is_none() {
            vfs::remove_dir(secret_path).await?;
        }
        if vault_path.read_dir()?.next().is_none() {
            vfs::remove_dir(vault_path).await?;
        }

        Ok(FileEvent::DeleteFile(
            SecretPath(*vault_id, *secret_id),
            *file_name,
        ))
    }

    /// Move a collection of external storage files.
    #[allow(clippy::too_many_arguments)]
    pub async fn move_files(
        &self,
        secret_data: &SecretRow,
        old_vault_id: &VaultId,
        new_vault_id: &VaultId,
        old_secret_id: &SecretId,
        new_secret_id: &SecretId,
        targets: Option<Vec<&Secret>>,
        file_progress: &mut Option<mpsc::Sender<FileProgress>>,
    ) -> Result<Vec<FileMutationEvent>> {
        let mut events = Vec::new();
        let targets = targets.unwrap_or_else(|| {
            get_external_file_secrets(secret_data.secret())
        });

        for target in targets {
            if let Secret::File {
                content: FileContent::External { checksum, name, .. },
                ..
            } = target
            {
                if let Some(file_progress) = file_progress.as_mut() {
                    let _ = file_progress
                        .send(FileProgress::Move {
                            name: name.to_owned(),
                        })
                        .await;
                }

                let file_name = ExternalFileName::from(checksum);
                events.push(
                    self.move_file(
                        old_vault_id,
                        new_vault_id,
                        old_secret_id,
                        new_secret_id,
                        &file_name,
                    )
                    .await?,
                );
            }
        }
        Ok(events)
    }

    /// Move the encrypted file for external file storage.
    pub(crate) async fn move_file(
        &self,
        old_vault_id: &VaultId,
        new_vault_id: &VaultId,
        old_secret_id: &SecretId,
        new_secret_id: &SecretId,
        file_name: &ExternalFileName,
    ) -> Result<FileMutationEvent> {
        let old_vault_path = self.paths.into_file_folder_path(old_vault_id);
        let old_secret_path = self
            .paths
            .into_file_secret_path(old_vault_id, old_secret_id);
        let old_path = self.paths.into_file_path_parts(
            old_vault_id,
            old_secret_id,
            file_name,
        );

        let new_path = self.paths.into_file_path_parts(
            new_vault_id,
            new_secret_id,
            file_name,
        );

        if let Some(parent) = new_path.parent() {
            if !vfs::try_exists(parent).await? {
                vfs::create_dir_all(parent).await?;
            }
        }

        vfs::rename(old_path, new_path).await?;

        // Prune empty directories
        let secret_dir_is_empty =
            old_secret_path.read_dir()?.next().is_none();
        if secret_dir_is_empty {
            vfs::remove_dir(old_secret_path).await?;
        }
        let vault_dir_is_empty = old_vault_path.read_dir()?.next().is_none();
        if vault_dir_is_empty {
            vfs::remove_dir(old_vault_path).await?;
        }

        let event = FileEvent::MoveFile {
            name: *file_name,
            from: SecretPath(*old_vault_id, *old_secret_id),
            dest: SecretPath(*new_vault_id, *new_secret_id),
        };

        Ok(FileMutationEvent::Move(event))
    }

    // Encrypt files and write to disc; afterwards update the
    // file checksum and size.
    async fn write_update_checksum(
        &mut self,
        summary: &Summary,
        mut secret_data: SecretRow,
        sources: Option<Vec<FileSource>>,
        file_progress: &mut Option<mpsc::Sender<FileProgress>>,
    ) -> Result<(Vec<FileMutationEvent>, Option<(SecretId, SecretRow)>)> {
        tracing::debug!(folder = ?summary.id(), "write_update_checksum");

        let mut results = Vec::new();

        let id = *secret_data.id();

        tracing::debug!(secret = ?id);

        let files =
            sources.unwrap_or_else(|| get_file_sources(secret_data.secret()));

        if !files.is_empty() {
            for source in files {
                tracing::debug!(source = ?source.path);

                if let Some(file_progress) = file_progress.as_mut() {
                    let _ = file_progress
                        .send(FileProgress::Write {
                            name: source.name.clone(),
                        })
                        .await;
                }
                let encrypted_file = self
                    .encrypt_file_storage(summary.id(), &id, &source.path)
                    .await?;

                let file_name = hex::encode(&encrypted_file.digest);
                tracing::debug!(checksum = %file_name);

                let mutation_data = (
                    FileStorageResult {
                        source,
                        encrypted_file,
                    },
                    FileEvent::CreateFile(
                        SecretPath(*summary.id(), id),
                        file_name.parse()?,
                    ),
                );
                results.push(mutation_data);
            }
        }

        let file = results.iter().find(|r| r.0.source.field_index.is_none());
        let mut attachments = Vec::new();
        for r in &results {
            if r.0.source.field_index.is_some() {
                attachments.push(r);
            }
        }

        let new_user_data = if !attachments.is_empty() {
            let mut user_data: UserData = Default::default();
            user_data.set_comment(
                secret_data
                    .secret()
                    .user_data()
                    .comment()
                    .map(|s| s.to_string()),
            );
            user_data.set_recovery_note(
                secret_data
                    .secret()
                    .user_data()
                    .recovery_note()
                    .map(|s| s.to_string()),
            );

            let mut fields = Vec::new();
            for (index, field) in
                secret_data.secret().user_data().fields().iter().enumerate()
            {
                if let Some(attachment) = attachments
                    .iter()
                    .find(|a| a.0.source.field_index == Some(index))
                {
                    fields.push(SecretRow::new(
                        *field.id(),
                        field.meta().clone(),
                        copy_file_secret(
                            field.secret(),
                            Some(attachment.0.encrypted_file.digest.clone()),
                            Some(attachment.0.encrypted_file.size),
                            None,
                        )?,
                    ));
                } else {
                    fields.push(field.clone());
                }
            }

            *user_data.fields_mut() = fields;
            Some(user_data)
        } else {
            None
        };

        let new_meta = secret_data.meta().clone();

        // Ensure we update checksum for top-level file
        // when this is a file secret type
        let (new_secret, changed) = if let Secret::File {
            content: FileContent::External { .. },
            ..
        } = secret_data.secret()
        {
            (
                copy_file_secret(
                    secret_data.secret(),
                    file.as_ref().map(|f| f.0.encrypted_file.digest.clone()),
                    file.as_ref().map(|f| f.0.encrypted_file.size),
                    new_user_data,
                )?,
                true,
            )
        } else if let Some(new_user_data) = new_user_data {
            *secret_data.secret_mut().user_data_mut() = new_user_data;
            let (_, _, secret) = secret_data.into();
            (secret, true)
        } else {
            let (_, _, secret) = secret_data.into();
            (secret, false)
        };

        let write_update = if changed {
            let secret_data = SecretRow::new(id, new_meta, new_secret);

            // Update with new checksum(s)
            // self.write_secret(&id, secret_data, false).await?;

            Some((id, secret_data))
        } else {
            None
        };

        let events = results
            .into_iter()
            .map(|data| FileMutationEvent::Create {
                result: data.0,
                event: data.1,
            })
            .collect::<Vec<_>>();
        Ok((events, write_update))
    }
}

fn get_file_sources(secret: &Secret) -> Vec<FileSource> {
    fn add_file_source(
        secret: &Secret,
        files: &mut Vec<FileSource>,
        field_index: Option<usize>,
    ) {
        if let Secret::File {
            content: FileContent::External { path, .. },
            ..
        } = secret
        {
            if path.is_some() {
                let name = basename(path.as_ref().unwrap());
                files.push(FileSource {
                    path: path.clone().unwrap(),
                    name,
                    field_index,
                });
            }
        }
    }

    let mut files = Vec::new();
    add_file_source(secret, &mut files, None);
    for (index, field) in secret.user_data().fields().iter().enumerate() {
        add_file_source(field.secret(), &mut files, Some(index));
    }
    files
}

fn get_external_file_secrets(secret: &Secret) -> Vec<&Secret> {
    let mut secrets = Vec::new();
    if let Secret::File {
        content: FileContent::External { .. },
        ..
    } = secret
    {
        secrets.push(secret);
    }
    for field in secret.user_data().fields() {
        if let Secret::File {
            content: FileContent::External { .. },
            ..
        } = field.secret()
        {
            secrets.push(field.secret());
        }
    }
    secrets
}

fn get_file_secret_diff<'a>(
    old_secret: &'a Secret,
    new_secret: &'a Secret,
) -> FileStorageDiff<'a> {
    let mut deleted = Vec::new();
    let mut unchanged = Vec::new();

    // Check if the top-level secret was unchanged
    if let Secret::File {
        content: FileContent::External { path, .. },
        ..
    } = new_secret
    {
        if path.is_none() {
            unchanged.push(new_secret);
        }
    }

    // Check if the top-level secret will be overwritten
    // so we delete the old files
    if let Secret::File {
        content: FileContent::External { path, .. },
        ..
    } = new_secret
    {
        if path.is_some() {
            deleted.push(old_secret);
        }
    }

    // Find attachments that are unchanged
    for field in new_secret.user_data().fields() {
        if let Secret::File {
            content: FileContent::External { path, .. },
            ..
        } = field.secret()
        {
            if path.is_none() {
                unchanged.push(field.secret());
            }
        }
    }

    // Find deleted attachments
    for field in old_secret.user_data().fields() {
        if let Secret::File {
            content: FileContent::External { path, .. },
            ..
        } = field.secret()
        {
            if path.is_none() {
                let existing =
                    new_secret.user_data().fields().iter().find(|other| {
                        // Must compare on secret as the label can
                        // be changed in a rename operation so comparing
                        // the fields would result in deleting the file
                        // when an attachment is renamed
                        return field.secret() == other.secret();
                    });

                if existing.is_none() {
                    deleted.push(field.secret());
                }
            }
        }
    }

    FileStorageDiff { deleted, unchanged }
}

// Get a copy of a file secret for modification.
fn copy_file_secret(
    secret: &Secret,
    new_checksum: Option<Vec<u8>>,
    new_size: Option<u64>,
    new_user_data: Option<UserData>,
) -> Result<Secret> {
    if let Secret::File {
        content:
            FileContent::External {
                name,
                mime,
                checksum,
                size,
                path,
            },
        user_data,
    } = secret
    {
        let checksum: [u8; 32] = if let Some(checksum) = new_checksum {
            checksum.as_slice().try_into()?
        } else {
            *checksum
        };

        Ok(Secret::File {
            content: FileContent::External {
                name: name.clone(),
                mime: mime.clone(),
                checksum,
                size: new_size.unwrap_or(*size),
                path: path.clone(),
            },
            user_data: new_user_data.unwrap_or_else(|| user_data.clone()),
        })
    } else {
        Err(Error::NotFileContent)
    }
}
