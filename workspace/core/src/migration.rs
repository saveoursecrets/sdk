//! Migration defines types that expose all
//! vaults and secrets insecurely and unencrypted
//! as a single JSON document for migrating to
//! another service.

use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io::Write};
use tar::{Builder, Header};

use crate::{
    archive::{deflate, finish_header},
    secret::{Secret, SecretId, SecretMeta, VaultMeta},
    vault::Summary,
    Gatekeeper, Result,
};

/// Create a compressed tar.gz public archive from the given files.
pub fn create_public_archive(files: HashMap<&str, &[u8]>) -> Result<Vec<u8>> {
    let mut archive = Vec::new();
    let mut writer = PublicArchive::new(&mut archive);

    for (path, buffer) in files {
        writer = writer.add_file(path, buffer)?;
    }
    writer.finish()?;

    // Compress the tarball
    let mut tar_gz = Vec::new();
    deflate(archive.as_slice(), &mut tar_gz)?;
    Ok(tar_gz)
}

/// Archive writer for a public migration.
pub struct PublicArchive<W: Write> {
    builder: Builder<W>,
}

impl<W: Write> PublicArchive<W> {
    /// Create a new writer.
    pub fn new(inner: W) -> Self {
        Self {
            builder: Builder::new(inner),
        }
    }

    /// Add a file to this archive.
    pub fn add_file(mut self, path: &str, buffer: &[u8]) -> Result<Self> {
        let mut header = Header::new_gnu();
        header.set_path(path)?;
        header.set_size(buffer.len() as u64);
        finish_header(&mut header);
        self.builder.append(&header, buffer)?;
        Ok(self)
    }

    /// Finish building the archive.
    pub fn finish(self) -> Result<W> {
        Ok(self.builder.into_inner()?)
    }
}

/// Migration encapsulates a collection of vaults
/// and their unencrypted secrets.
#[derive(Default, Serialize, Deserialize)]
pub struct PublicMigration {
    vaults: Vec<PublicStore>,
}

impl PublicMigration {
    /// Add the secrets in a vault to this migration.
    ///
    /// The passed `Gatekeeper` must already be unlocked so the
    /// secrets can be decrypted.
    pub fn add(&mut self, access: &Gatekeeper) -> Result<()> {
        let meta = access.vault_meta()?;

        let mut store: PublicStore = Default::default();
        store.summary = access.vault().summary().clone();
        store.meta = meta;

        for id in access.vault().keys() {
            if let Some((meta, secret, _)) = access.read(id)? {
                store.secrets.push(PublicSecret {
                    id: *id,
                    meta: meta,
                    secret: secret,
                });
            }
        }

        self.vaults.push(store);
        Ok(())
    }
}

/// Public store is an insecure, unencrypted representation of a vault.
#[derive(Default, Serialize, Deserialize)]
pub struct PublicStore {
    /// The vault summary information.
    summary: Summary,
    /// The vault meta data.
    meta: VaultMeta,
    /// The collection of secrets in the vault.
    secrets: Vec<PublicSecret>,
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
        generate_passphrase, test_utils::*, vault::Vault, Gatekeeper,
    };

    fn create_mock_migration() -> Result<PublicMigration> {
        let (passphrase, _) = generate_passphrase()?;

        let mut vault: Vault = Default::default();
        vault.set_default_flag(true);
        vault.initialize(passphrase.expose_secret())?;

        let mut keeper = Gatekeeper::new(vault, None);
        let mut migration: PublicMigration = Default::default();

        keeper.unlock(passphrase.expose_secret())?;

        let (meta, secret, _, _) =
            mock_secret_note("Mock note", "Value for the mock note")?;

        keeper.create(meta, secret)?;
        migration.add(&keeper)?;

        Ok(migration)
    }

    #[test]
    fn migration_json_encode() -> Result<()> {
        let migration = create_mock_migration()?;
        let _public_json = serde_json::to_string_pretty(&migration)?;
        //println!("{}", public_json);
        Ok(())
    }

    #[test]
    fn migration_public_archive() -> Result<()> {
        let migration = create_mock_migration()?;
        let public_json = serde_json::to_vec_pretty(&migration)?;

        let mut files = HashMap::new();
        files.insert("public-unsafe.json", public_json.as_slice());

        // Check creating an archive
        let archive = create_public_archive(files)?;

        Ok(())
    }
}
