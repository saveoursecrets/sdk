//! Migration defines types that expose all
//! vaults and secrets insecurely and unencrypted
//! as a compressed archive for migrating to
//! another service.

use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io::Write};
use tar::Builder;

use crate::{
    archive::append_long_path,
    secret::{Secret, SecretId, SecretMeta, VaultMeta},
    vault::{Summary, VaultId},
    Gatekeeper, Result,
};

/// Migration encapsulates a collection of vaults
/// and their unencrypted secrets.
pub struct PublicExport<W: Write> {
    builder: Builder<W>,
    vault_ids: Vec<VaultId>,
}

impl<W: Write> PublicExport<W> {
    /// Create a new public migration.
    pub fn new(inner: W) -> Self {
        Self {
            builder: Builder::new(inner),
            vault_ids: Vec::new(),
        }
    }

    /// Add the secrets in a vault to this migration.
    ///
    /// The passed `Gatekeeper` must already be unlocked so the
    /// secrets can be decrypted.
    pub fn add(&mut self, access: &Gatekeeper) -> Result<()> {
        // This verifies decryption early, if the keeper is locked
        // it will error here
        let meta = access.vault_meta()?;

        let vault_id = access.summary().id();
        let base_path = format!("vaults/{}", vault_id);
        let file_path = format!("{}/files", base_path);

        let store = PublicVaultInfo {
            meta: meta,
            summary: access.summary().clone(),
            secrets: access.vault().keys().copied().collect(),
        };
        let store_path = format!("{}/meta.json", base_path);
        let buffer = serde_json::to_vec_pretty(&store)?;
        append_long_path(&mut self.builder, &store_path, buffer.as_slice())?;

        for id in access.vault().keys() {
            if let Some((meta, mut secret, _)) = access.read(id)? {
                if let Secret::File { buffer, checksum, .. } = &mut secret {
                    let path =
                        format!("{}/{}", file_path, hex::encode(checksum));
                    append_long_path(
                        &mut self.builder,
                        &path,
                        buffer.expose_secret().as_slice(),
                    )?;
                    *buffer = secrecy::Secret::new(vec![]);
                }

                // FIXME: handle attachments

                let path = format!("{}/{}.json", base_path, id);
                let public_secret = PublicSecret {
                    id: *id,
                    meta: meta,
                    secret: secret,
                };

                let buffer = serde_json::to_vec_pretty(&public_secret)?;
                append_long_path(
                    &mut self.builder,
                    &path,
                    buffer.as_slice(),
                )?;
            }
        }

        self.vault_ids.push(*vault_id);
        Ok(())
    }

    /// Append additional files to the archive.
    pub fn append_files(
        &mut self,
        files: HashMap<&str, &[u8]>,
    ) -> Result<()> {
        for (path, buffer) in files {
            append_long_path(&mut self.builder, path, buffer)?;
        }
        Ok(())
    }

    /// Finish building the archive.
    pub fn finish(mut self) -> Result<W> {
        // Add the collection of vault identifiers
        let path = format!("vaults.json");
        let buffer = serde_json::to_vec_pretty(&self.vault_ids)?;
        append_long_path(
            &mut self.builder,
            &path,
            buffer.as_slice(),
        )?;

        Ok(self.builder.into_inner()?)
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
    use secrecy::ExposeSecret;

    use super::*;
    use crate::{
        archive::deflate,
        generate_passphrase, test_utils::*, vault::Vault, Gatekeeper,
    };

    fn create_mock_migration<W: Write>(
        writer: W,
    ) -> Result<PublicExport<W>> {
        let (passphrase, _) = generate_passphrase()?;

        let mut vault: Vault = Default::default();
        vault.set_default_flag(true);
        vault.initialize(passphrase.expose_secret())?;

        let mut migration = PublicExport::new(writer);
        let mut keeper = Gatekeeper::new(vault, None);
        keeper.unlock(passphrase.expose_secret())?;

        let (meta, secret, _, _) =
            mock_secret_note("Mock note", "Value for the mock note")?;
        keeper.create(meta, secret)?;

        let (meta, secret, _, _) = mock_secret_file(
            "Mock file",
            "test.txt",
            "text/plain",
            "Test value".as_bytes().to_vec(),
        )?;
        keeper.create(meta, secret)?;

        migration.add(&keeper)?;
        Ok(migration)
    }

    #[test]
    fn migration_public_archive() -> Result<()> {
        let mut archive = Vec::new();
        let migration = create_mock_migration(&mut archive)?;
        let archive = migration.finish()?;
        let mut tar_gz = Vec::new();
        deflate(archive.as_slice(), &mut tar_gz)?;
        
        Ok(())
    }
}
