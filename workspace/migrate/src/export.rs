//! Export an archive of unencrypted secrets.
//!
//! Used to migrate to another service.

use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io::{Seek, Write},
};
use zip::{write::FileOptions, CompressionMethod, ZipWriter};

use sos_sdk::{
    vault::{
        secret::{FileContent, Secret, SecretId, SecretMeta},
        Gatekeeper, Summary, VaultId, VaultMeta,
    },
    Result,
};

/// Migration encapsulates a collection of vaults
/// and their unencrypted secrets.
pub struct PublicExport<W: Write + Seek> {
    builder: ZipWriter<W>,
    vault_ids: Vec<VaultId>,
}

impl<W: Write + Seek> PublicExport<W> {
    /// Create a new public migration.
    pub fn new(inner: W) -> Self {
        Self {
            builder: ZipWriter::new(inner),
            vault_ids: Vec::new(),
        }
    }

    fn append_file_buffer(
        &mut self,
        path: &str,
        buffer: &[u8],
    ) -> Result<()> {
        //let now = OffsetDateTime::now_utc();
        let options = FileOptions::default()
            .compression_method(CompressionMethod::Stored);
        // FIXME:
        //let options = options.last_modified_time(now.try_into()?);
        self.builder.start_file(path, options)?;
        self.builder.write_all(buffer)?;
        Ok(())
    }

    /// Add the secrets in a vault to this migration.
    ///
    /// The passed `Gatekeeper` must already be unlocked so the
    /// secrets can be decrypted.
    pub async fn add(&mut self, access: &Gatekeeper) -> Result<()> {
        // This verifies decryption early, if the keeper is locked
        // it will error here
        let meta = access.vault_meta()?;

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
        self.append_file_buffer(&store_path, buffer.as_slice())?;

        for id in access.vault().keys() {
            if let Some((meta, mut secret, _)) = access.read(id).await? {
                // Move contents for file secrets
                self.move_file_buffer(&file_path, &mut secret)?;

                // Move contents for file attachments
                for field in secret.user_data_mut().fields_mut() {
                    self.move_file_buffer(&file_path, field.secret_mut())?;
                }

                let path = format!("{}/{}.json", base_path, id);
                let public_secret = PublicSecret {
                    id: *id,
                    meta,
                    secret,
                };

                let buffer = serde_json::to_vec_pretty(&public_secret)?;
                self.append_file_buffer(&path, buffer.as_slice())?;
            }
        }

        self.vault_ids.push(*vault_id);
        Ok(())
    }

    /// Take an embedded file secret and move the buffer to an entry in the archive.
    fn move_file_buffer(
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
                )?;

                // Clear the buffer so the export does not encode the bytes
                // in the JSON document
                *buffer = secrecy::Secret::new(vec![]);
            }
        }
        Ok(())
    }

    /// Append additional files to the archive.
    pub fn append_files(
        &mut self,
        files: HashMap<&str, &[u8]>,
    ) -> Result<()> {
        for (path, buffer) in files {
            self.append_file_buffer(path, buffer)?;
        }
        Ok(())
    }

    /// Finish building the archive.
    pub fn finish(mut self) -> Result<W> {
        // Add the collection of vault identifiers
        let path = "vaults.json";
        let buffer = serde_json::to_vec_pretty(&self.vault_ids)?;
        self.append_file_buffer(path, buffer.as_slice())?;

        Ok(self.builder.finish()?)
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

    use super::*;
    use sos_sdk::{
        passwd::diceware::generate_passphrase,
        test_utils::*,
        vault::{Gatekeeper, Vault},
    };

    async fn create_mock_migration<W: Write + Seek>(
        writer: W,
    ) -> Result<PublicExport<W>> {
        let (passphrase, _) = generate_passphrase()?;

        let mut vault: Vault = Default::default();
        vault.set_default_flag(true);
        vault.initialize(passphrase.clone(), None)?;

        let mut migration = PublicExport::new(writer);
        let mut keeper = Gatekeeper::new(vault, None);
        keeper.unlock(passphrase)?;

        let (meta, secret, _, _) =
            mock_secret_note("Mock note", "Value for the mock note")?;
        keeper.create(meta, secret).await?;

        let (meta, secret, _, _) = mock_secret_file(
            "Mock file",
            "test.txt",
            "text/plain",
            "Test value".as_bytes().to_vec(),
        )?;
        keeper.create(meta, secret).await?;

        migration.add(&keeper).await?;
        Ok(migration)
    }

    #[tokio::test]
    async fn migration_public_archive() -> Result<()> {
        let mut archive = Vec::new();
        let migration =
            create_mock_migration(Cursor::new(&mut archive)).await?;
        let _ = migration.finish()?;
        Ok(())
    }
}
