//! File manager to keep external files in sync
//! as secrets are created, updated and moved.

use std::path::{Path, PathBuf};

use sos_sdk::{
    account::DelegatedPassphrase,
    secrecy::{ExposeSecret, SecretVec},
    storage::EncryptedFile,
    storage::{basename, FileStorage, StorageDirs},
    vault::{
        secret::{Secret, SecretData, SecretId, UserData, UserField},
        Summary, VaultId,
    },
};

use crate::client::{user::UserStorage, Error, Result};

/// Diff of file secrets.
struct FileStorageDiff<'a> {
    /// File secrets that have been deleted.
    deleted: Vec<&'a Secret>,
    /// File secrets that have not changed.
    unchanged: Vec<&'a Secret>,
}

/// Source path to a file.
#[derive(Clone)]
struct FileSource {
    /// Path to the source file.
    path: PathBuf,
    /// Name of the file.
    name: String,
    /// Field index for attachments.
    field_index: Option<usize>,
}

/// Result of encrypting an external file.
#[derive(Clone)]
pub struct FileStorageResult {
    /// Source for the file.
    source: FileSource,
    /// Encrypted file data.
    encrypted_file: EncryptedFile,
}

impl UserStorage {
    /// Encrypt a file and move it to the external file storage location.
    pub fn encrypt_file_storage<P: AsRef<Path>>(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        source: P,
    ) -> Result<EncryptedFile> {
        // Find the file encryption password
        let password = DelegatedPassphrase::find_file_encryption_passphrase(
            self.user.identity().keeper(),
        )?;

        // Encrypt and write to disc
        Ok(FileStorage::encrypt_file_storage(
            password,
            source,
            self.user.identity().address().to_string(),
            vault_id.to_string(),
            secret_id.to_string(),
        )?)
    }

    /// Decrypt a file in the storage location and return the buffer.
    pub fn decrypt_file_storage(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &str,
    ) -> Result<Vec<u8>> {
        // Find the file encryption password
        let password = DelegatedPassphrase::find_file_encryption_passphrase(
            self.user.identity().keeper(),
        )?;

        Ok(FileStorage::decrypt_file_storage(
            &password,
            self.user.identity().address().to_string(),
            vault_id.to_string(),
            secret_id.to_string(),
            file_name,
        )?)
    }

    /// Expected location for a file by convention.
    pub fn file_location(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &str,
    ) -> Result<PathBuf> {
        Ok(StorageDirs::file_location(
            self.user.identity().address().to_string(),
            vault_id.to_string(),
            secret_id.to_string(),
            file_name,
        )?)
    }

    /// Move the encrypted file for external file storage.
    pub fn move_file(
        &self,
        old_vault_id: &VaultId,
        new_vault_id: &VaultId,
        old_secret_id: &SecretId,
        new_secret_id: &SecretId,
        file_name: &str,
    ) -> Result<()> {
        let old_vault_path = self.files_dir.join(old_vault_id.to_string());
        let old_secret_path = old_vault_path.join(old_secret_id.to_string());
        let old_path = old_secret_path.join(file_name);

        let new_path = self
            .files_dir
            .join(new_vault_id.to_string())
            .join(new_secret_id.to_string())
            .join(file_name);

        if let Some(parent) = new_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }

        std::fs::rename(old_path, new_path)?;

        // Prune empty directories
        let secret_dir_is_empty =
            old_secret_path.read_dir()?.next().is_none();
        if secret_dir_is_empty {
            std::fs::remove_dir(old_secret_path)?;
        }
        let vault_dir_is_empty = old_vault_path.read_dir()?.next().is_none();
        if vault_dir_is_empty {
            std::fs::remove_dir(old_vault_path)?;
        }

        Ok(())
    }

    /// Delete a file from the storage location.
    pub fn delete_file(
        &self,
        vault_id: &VaultId,
        secret_id: &SecretId,
        file_name: &str,
    ) -> Result<()> {
        let vault_path = self.files_dir.join(vault_id.to_string());
        let secret_path = vault_path.join(secret_id.to_string());
        let path = secret_path.join(file_name);

        std::fs::remove_file(path)?;

        // Prune empty directories
        let secret_dir_is_empty = secret_path.read_dir()?.next().is_none();
        if secret_dir_is_empty {
            std::fs::remove_dir(secret_path)?;
        }
        let vault_dir_is_empty = vault_path.read_dir()?.next().is_none();
        if vault_dir_is_empty {
            std::fs::remove_dir(vault_path)?;
        }

        Ok(())
    }

    /// Create external files when a file secret is created.
    pub(crate) async fn create_files(
        &mut self,
        summary: &Summary,
        secret_data: SecretData,
    ) -> Result<Vec<FileStorageResult>> {
        self.write_update_checksum(summary, secret_data, None).await
    }

    /// Update external files when a file secret is updated.
    pub(crate) async fn update_files(
        &mut self,
        old_summary: &Summary,
        new_summary: &Summary,
        old_secret: &SecretData,
        new_secret: SecretData,
    ) -> Result<Vec<FileStorageResult>> {
        let mut results = Vec::new();

        let old_secret_id =
            old_secret.id.as_ref().ok_or_else(|| Error::NoSecretId)?;
        let new_secret_id =
            new_secret.id.as_ref().ok_or_else(|| Error::NoSecretId)?;

        let has_moved =
            new_summary != old_summary || new_secret.id != old_secret.id;

        let diff =
            get_file_secret_diff(&old_secret.secret, &new_secret.secret);

        let changed_files = get_file_sources(&new_secret.secret);
        let deleted = diff.deleted;
        let unchanged_files = diff.unchanged;

        // Delete any attachments that no longer exist
        if !deleted.is_empty() {
            self.delete_files(old_summary, old_secret, Some(deleted))
                .await?;
        }

        // Move unchanged files
        if has_moved {
            self.move_files(
                &new_secret,
                old_summary.id(),
                new_summary.id(),
                old_secret_id,
                new_secret_id,
                Some(unchanged_files),
            )
            .await?;
        }

        // Write changed files to the new location
        if !changed_files.is_empty() {
            let written = self
                .write_update_checksum(
                    new_summary,
                    new_secret,
                    Some(changed_files),
                )
                .await?;
            results.extend_from_slice(&written);
        }

        Ok(results)
    }

    /// Delete a collection of files from the external storage.
    pub(crate) async fn delete_files(
        &self,
        summary: &Summary,
        secret_data: &SecretData,
        targets: Option<Vec<&Secret>>,
    ) -> Result<()> {
        let id = secret_data.id.as_ref().ok_or_else(|| Error::NoSecretId)?;
        let targets = targets.unwrap_or_else(|| {
            get_external_file_secrets(&secret_data.secret)
        });
        for target in targets {
            if let Secret::File { checksum, .. } = target {
                let file_name = hex::encode(checksum);
                self.delete_file(summary.id(), id, &file_name)?;
            }
        }
        Ok(())
    }

    /// Move a collection of external storage files.
    pub(crate) async fn move_files(
        &self,
        secret_data: &SecretData,
        old_vault_id: &VaultId,
        new_vault_id: &VaultId,
        old_secret_id: &SecretId,
        new_secret_id: &SecretId,
        targets: Option<Vec<&Secret>>,
    ) -> Result<()> {
        let targets = targets.unwrap_or_else(|| {
            get_external_file_secrets(&secret_data.secret)
        });

        for target in targets {
            if let Secret::File { checksum, .. } = target {
                let file_name = hex::encode(checksum);

                self.move_file(
                    old_vault_id,
                    new_vault_id,
                    old_secret_id,
                    new_secret_id,
                    &file_name,
                )?;
            }
        }
        Ok(())
    }

    // Encrypt files and write to disc; afterwards update the
    // file checksum and size.
    async fn write_update_checksum(
        &mut self,
        summary: &Summary,
        mut secret_data: SecretData,
        sources: Option<Vec<FileSource>>,
    ) -> Result<Vec<FileStorageResult>> {
        let mut results = Vec::new();

        let id = secret_data.id.as_ref().ok_or_else(|| Error::NoSecretId)?;

        let files =
            sources.unwrap_or_else(|| get_file_sources(&secret_data.secret));
        if !files.is_empty() {
            for source in files {
                let encrypted_file = self.encrypt_file_storage(
                    summary.id(),
                    id,
                    &source.path,
                )?;
                results.push(FileStorageResult {
                    source,
                    encrypted_file,
                });
            }
        }

        let file = results.iter().find(|r| r.source.field_index.is_none());
        let mut attachments = Vec::new();
        for r in &results {
            if r.source.field_index.is_some() {
                attachments.push(r);
            }
        }

        let new_user_data = if !attachments.is_empty() {
            let mut user_data: UserData = Default::default();
            user_data.set_comment(
                secret_data
                    .secret
                    .user_data()
                    .comment()
                    .map(|s| s.to_string()),
            );
            user_data.set_recovery_note(
                secret_data
                    .secret
                    .user_data()
                    .recovery_note()
                    .map(|s| s.to_string()),
            );

            let mut fields = Vec::new();
            for (index, field) in secret_data
                .secret
                .user_data()
                .fields()
                .into_iter()
                .enumerate()
            {
                if let Some(attachment) = attachments
                    .iter()
                    .find(|a| a.source.field_index == Some(index))
                {
                    if let UserField::Embedded { meta, secret, .. } = field {
                        fields.push(UserField::Embedded {
                            meta: meta.clone(),
                            secret: copy_file_secret(
                                &secret,
                                Some(
                                    attachment.encrypted_file.digest.clone(),
                                ),
                                Some(attachment.encrypted_file.size),
                                None,
                            )?,
                        });
                    }
                }
            }

            Some(user_data)
        } else {
            None
        };

        // Ensure we update checksum for top-level file
        // when this is a file secret type
        let new_secret = if let Secret::File { .. } = &secret_data.secret {
            copy_file_secret(
                &secret_data.secret,
                file.as_ref().map(|f| f.encrypted_file.digest.clone()),
                file.as_ref().map(|f| f.encrypted_file.size),
                new_user_data,
            )?
        } else {
            if let Some(new_user_data) = new_user_data {
                *secret_data.secret.user_data_mut() = new_user_data;
                secret_data.secret
            } else {
                secret_data.secret
            }
        };

        let secret_data = SecretData {
            id: Some(*id),
            meta: secret_data.meta,
            secret: new_secret,
        };

        // Update with new checksum(s)
        self.write_secret(id, secret_data, Some(summary.clone()))
            .await?;

        Ok(results)
    }
}

fn get_file_sources(secret: &Secret) -> Vec<FileSource> {
    fn add_file_source(secret: &Secret, files: &mut Vec<FileSource>) {
        if let Secret::File { external, path, .. } = secret {
            if *external && path.is_some() {
                let name = basename(path.as_ref().unwrap());
                files.push(FileSource {
                    path: path.clone().unwrap(),
                    name,
                    field_index: None,
                });
            }
        }
    }

    let mut files = Vec::new();
    add_file_source(&secret, &mut files);
    for field in secret.user_data().fields() {
        if let UserField::Embedded { secret, .. } = field {
            add_file_source(secret, &mut files);
        }
    }
    files
}

fn get_external_file_secrets(secret: &Secret) -> Vec<&Secret> {
    let mut secrets = Vec::new();
    if let Secret::File { external, .. } = secret {
        if *external {
            secrets.push(secret);
        }
    }
    for field in secret.user_data().fields() {
        if let UserField::Embedded { secret, .. } = field {
            if let Secret::File { external, .. } = secret {
                if *external {
                    secrets.push(secret);
                }
            }
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
    if let Secret::File { external, path, .. } = new_secret {
        if *external && path.is_none() {
            unchanged.push(new_secret);
        }
    }

    // Check if the top-level secret will be overwritten
    // so we delete the old files
    if let Secret::File { external, path, .. } = new_secret {
        if *external && path.is_some() {
            deleted.push(old_secret);
        }
    }

    // Find attachments that are unchanged
    for field in new_secret.user_data().fields() {
        if let UserField::Embedded { secret, .. } = field {
            if let Secret::File { external, path, .. } = secret {
                if *external && path.is_none() {
                    unchanged.push(secret);
                }
            }
        }
    }

    // Find deleted attachments
    for field in old_secret.user_data().fields() {
        if let UserField::Embedded { secret, .. } = field {
            if let Secret::File { external, path, .. } = secret {
                if *external && path.is_none() {
                    let existing =
                        new_secret.user_data().fields().into_iter().find(
                            |other| {
                                if let UserField::Embedded {
                                    secret: other_secret,
                                    ..
                                } = other
                                {
                                    // Must compare on secret as the label can
                                    // be changed in a rename operation so comparing
                                    // the fields would result in deleting the file
                                    // when an attachment is renamed
                                    return secret == other_secret;
                                }
                                false
                            },
                        );

                    if existing.is_none() {
                        deleted.push(secret);
                    }
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
        name,
        mime,
        buffer,
        checksum,
        external,
        size,
        path,
        user_data,
    } = secret
    {
        let checksum: [u8; 32] = if let Some(checksum) = new_checksum {
            checksum.as_slice().try_into()?
        } else {
            *checksum
        };

        Ok(Secret::File {
            name: name.clone(),
            mime: mime.clone(),
            buffer: SecretVec::new(buffer.expose_secret().to_vec()),
            checksum,
            external: *external,
            size: new_size.unwrap_or_else(|| *size),
            path: path.clone(),
            user_data: new_user_data.unwrap_or_else(|| user_data.clone()),
        })
    } else {
        Err(Error::NotFileSecret)
    }
}
