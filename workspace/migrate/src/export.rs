//! Export an archive of unencrypted secrets.
//!
//! Used to migrate to another service.

use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use async_zip::{tokio::write::ZipFileWriter, Compression, ZipEntryBuilder};
use tokio::io::AsyncWrite;
use tokio_util::compat::Compat;

use sos_sdk::{
    vault::{
        secret::{FileContent, Secret, SecretId, SecretMeta},
        Gatekeeper, Summary, VaultId, VaultMeta,
    },
    Result,
};

/// Migration encapsulates a collection of vaults
/// and their unencrypted secrets.
pub struct PublicExport<W: AsyncWrite + Unpin> {
    writer: ZipFileWriter<W>,
    vault_ids: Vec<VaultId>,
}

impl<W: AsyncWrite + Unpin> PublicExport<W> {
    /// Create a new public migration.
    pub fn new(inner: W) -> Self {
        Self {
            writer: ZipFileWriter::with_tokio(inner),
            vault_ids: Vec::new(),
        }
    }

    async fn append_file_buffer(
        &mut self,
        path: &str,
        buffer: &[u8],
    ) -> Result<()> {
        // FIXME: set last modified time to now
        let entry = ZipEntryBuilder::new(path.into(), Compression::Deflate);
        self.writer.write_entry_whole(entry, buffer).await?;
        Ok(())
    }

    /// Add the secrets in a vault to this migration.
    ///
    /// The passed `Gatekeeper` must already be unlocked so the
    /// secrets can be decrypted.
    pub async fn add(&mut self, access: &Gatekeeper) -> Result<()> {
        // This verifies decryption early, if the keeper is locked
        // it will error here
        let meta = access.vault_meta().await?;

        let vault_id = access.summary().id();
        let base_path = format!("vaults/{}", vault_id);
        let file_path = format!("{}/files", base_path);

        let store = PublicVaultInfo {
            meta,
            summary: access.summary().clone(),
            secrets: access.vault().keys().copied().collect(),
        };
        let store_path = format!("{}/meta.json", base_path);
        let buffer = serde_json::to_vec_pretty(&store)?;
        self.append_file_buffer(&store_path, buffer.as_slice())
            .await?;

        for id in access.vault().keys() {
            if let Some((meta, mut secret, _)) = access.read(id).await? {
                // Move contents for file secrets
                self.move_file_buffer(&file_path, &mut secret).await?;

                // Move contents for file attachments
                for field in secret.user_data_mut().fields_mut() {
                    self.move_file_buffer(&file_path, field.secret_mut())
                        .await?;
                }

                let path = format!("{}/{}.json", base_path, id);
                let public_secret = PublicSecret {
                    id: *id,
                    meta,
                    secret,
                };

                let buffer = serde_json::to_vec_pretty(&public_secret)?;
                self.append_file_buffer(&path, buffer.as_slice()).await?;
            }
        }

        self.vault_ids.push(*vault_id);
        Ok(())
    }

    /// Take an embedded file secret and move the
    /// buffer to an entry in the archive.
    async fn move_file_buffer(
        &mut self,
        file_path: &str,
        secret: &mut Secret,
    ) -> Result<()> {
        if let Secret::File { content, .. } = secret {
            if let FileContent::Embedded {
                buffer, checksum, ..
            } = content
            {
                let path = format!("{}/{}", file_path, hex::encode(checksum));

                // Write the file buffer to the archive
                self.append_file_buffer(
                    &path,
                    buffer.expose_secret().as_slice(),
                )
                .await?;

                // Clear the buffer so the export does not encode the bytes
                // in the JSON document
                *buffer = secrecy::Secret::new(vec![]);
            }
        }
        Ok(())
    }

    /// Append additional files to the archive.
    pub async fn append_files(
        &mut self,
        files: HashMap<&str, &[u8]>,
    ) -> Result<()> {
        for (path, buffer) in files {
            self.append_file_buffer(path, buffer).await?;
        }
        Ok(())
    }

    /// Finish building the archive.
    pub async fn finish(mut self) -> Result<Compat<W>> {
        // Add the collection of vault identifiers
        let path = "vaults.json";
        let buffer = serde_json::to_vec_pretty(&self.vault_ids)?;
        self.append_file_buffer(path, buffer.as_slice()).await?;

        Ok(self.writer.close().await?)
    }
}

/// Public vault info contains meta data about the vault and lists the
/// secret identifiers.
#[derive(Default, Serialize, Deserialize)]
pub struct PublicVaultInfo {
    /// The vault summary information.
    summary: Summary,
    /// The vault meta data.
    meta: VaultMeta,
    /// The collection of secrets in the vault.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    secrets: Vec<SecretId>,
}

/// Public secret is an insecure, unencrypted representation of a secret.
#[derive(Default, Serialize, Deserialize)]
pub struct PublicSecret {
    /// The secret identifier.
    id: SecretId,
    /// The secret meta data.
    meta: SecretMeta,
    /// The secret data.
    secret: Secret,
}

#[cfg(test)]
mod test {
    use anyhow::Result;

    use std::io::Cursor;
    use tokio::io::{AsyncSeek, AsyncWrite};

    use super::*;
    use sos_sdk::{
        passwd::diceware::generate_passphrase,
        test_utils::*,
        vault::{secret::SecretId, Gatekeeper, VaultBuilder, VaultFlags},
    };

    async fn create_mock_migration<W: AsyncWrite + AsyncSeek + Unpin>(
        writer: W,
    ) -> Result<PublicExport<W>> {
        let (passphrase, _) = generate_passphrase()?;

        let vault = VaultBuilder::new()
            .flags(VaultFlags::DEFAULT)
            .password(passphrase.clone(), None)
            .await?;

        let mut migration = PublicExport::new(writer);
        let mut keeper = Gatekeeper::new(vault);
        keeper.unlock(passphrase.into()).await?;

        let (meta, secret, _, _) =
            mock_secret_note("Mock note", "Value for the mock note").await?;
        keeper.create(SecretId::new_v4(), meta, secret).await?;

        let (meta, secret, _, _) = mock_secret_file(
            "Mock file",
            "test.txt",
            "text/plain",
            "Test value".as_bytes().to_vec(),
        )
        .await?;
        keeper.create(SecretId::new_v4(), meta, secret).await?;

        migration.add(&keeper).await?;
        Ok(migration)
    }

    #[tokio::test]
    async fn migration_public_archive() -> Result<()> {
        let mut archive = Vec::new();
        let migration =
            create_mock_migration(Cursor::new(&mut archive)).await?;
        let _ = migration.finish().await?;
        Ok(())
    }
}
