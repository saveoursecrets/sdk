//! Export and import archives for any backend target.
use crate::{BackendTarget, Error, Result};
use serde::Serialize;
use sos_archive::ZipReader;
use sos_core::{AccountId, ArchiveManifestVersion, PublicIdentity};
use sos_database::archive::ManifestVersion3;
use sos_filesystem::archive::ManifestVersion1;
use sos_vfs::File;
use std::path::Path;
use tokio::io::BufReader;

/// Enumeration of possible backup archive manifests
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum ArchiveManifest {
    /// Version 1 manifest.
    V1(ManifestVersion1),
    /// Version 2 manifest.
    V2(ManifestVersion1),
    /// Version 3 manifest.
    V3(ManifestVersion3),
}

impl ArchiveManifest {
    /// Version of the archive manifest.
    pub fn version(&self) -> ArchiveManifestVersion {
        match self {
            Self::V1(_) => ArchiveManifestVersion::V1,
            Self::V2(_) => ArchiveManifestVersion::V2,
            Self::V3(_) => ArchiveManifestVersion::V3,
        }
    }
}

/// Try to read the manifest in a backup archive.
pub async fn try_read_backup_archive_manifest(
    input: impl AsRef<Path>,
) -> Result<ArchiveManifest> {
    let file = BufReader::new(File::open(input.as_ref()).await?);
    let mut zip = ZipReader::new(file).await?;

    match zip.find_manifest::<ManifestVersion1>().await {
        Ok(Some(manifest)) => match manifest.version.as_ref() {
            Some(ArchiveManifestVersion::V1) => {
                Ok(ArchiveManifest::V1(manifest))
            }
            Some(ArchiveManifestVersion::V2) => {
                Ok(ArchiveManifest::V2(manifest))
            }
            _ => Ok(ArchiveManifest::V1(manifest)),
        },
        Ok(None) => {
            Err(Error::NotValidBackupArchive(input.as_ref().to_owned()))
        }
        Err(sos_archive::Error::Json(_)) => {
            if let Some(manifest) =
                zip.find_manifest::<ManifestVersion3>().await?
            {
                Ok(ArchiveManifest::V3(manifest))
            } else {
                Err(Error::NotValidBackupArchive(input.as_ref().to_owned()))
            }
        }
        Err(e) => Err(e.into()),
    }
}

/// Try to list the accounts in a backup archive.
pub async fn try_list_backup_archive_accounts(
    input: impl AsRef<Path>,
) -> Result<Vec<PublicIdentity>> {
    let manifest = try_read_backup_archive_manifest(input.as_ref()).await?;

    match manifest {
        // Versions 1 and 2 only support a single account
        ArchiveManifest::V1(manifest) | ArchiveManifest::V2(manifest) => {
            use sos_core::{constants::VAULT_EXT, decode};
            use sos_vault::Vault;
            let file = File::open(input.as_ref()).await?;
            let mut zip_reader = ZipReader::new(BufReader::new(file)).await?;
            let name =
                format!("{}.{}", manifest.account_id.to_string(), VAULT_EXT);
            if let Some(identity_buffer) = zip_reader.by_name(&name).await? {
                let identity_vault: Vault = decode(&identity_buffer).await?;
                let label = identity_vault.name().to_owned();
                let identity =
                    PublicIdentity::new(manifest.account_id, label);
                Ok(vec![identity])
            } else {
                Err(Error::NotValidBackupArchive(input.as_ref().to_owned()))
            }
        }
        // Version 3 backup archives can contain multiple accounts
        ArchiveManifest::V3(_) => {
            use sos_core::Paths;
            use sos_database::archive;
            use tempfile::tempdir;

            let temp = tempdir()?;
            let paths = Paths::new_client(temp.path());

            let mut import = archive::import_backup_archive(
                paths.database_file(),
                &*paths,
                input.as_ref(),
            )
            .await?;

            // Run migrations on the source to ensure it's
            // schema is up to date.
            import.migrate_source()?;

            let accounts = import.list_source_accounts()?;
            Ok(accounts.into_iter().map(|a| a.identity).collect())
        }
    }
}

/// Create a backup archive.
pub async fn export_backup_archive(
    output: impl AsRef<Path>,
    target: &BackendTarget,
    account_id: &AccountId,
) -> Result<()> {
    match target {
        BackendTarget::FileSystem(paths) => {
            use sos_filesystem::archive;
            let paths = paths.with_account_id(&account_id);
            archive::export_backup_archive(
                output.as_ref(),
                &account_id,
                &*paths,
            )
            .await?;
        }
        BackendTarget::Database(paths, _) => {
            use sos_database::archive;
            let db_path = paths.database_file();
            archive::export_backup_archive(db_path, paths, output.as_ref())
                .await?;
        }
    }

    Ok(())
}

/// Import from a backup archive.
pub async fn import_backup_archive(
    input: impl AsRef<Path>,
    target: &BackendTarget,
) -> Result<Vec<PublicIdentity>> {
    let accounts = match target {
        BackendTarget::FileSystem(paths) => {
            use sos_filesystem::archive;
            let account =
                archive::import_backup_archive(input.as_ref(), &paths)
                    .await?;
            vec![account]
        }
        BackendTarget::Database(paths, _) => {
            use sos_database::archive;

            let mut import = archive::import_backup_archive(
                paths.database_file(),
                paths,
                input.as_ref(),
            )
            .await?;

            // Run migrations on the source to ensure it's
            // schema is up to date.
            import.migrate_source()?;

            // Run migrations on the target database to
            // ensure schema is up to date
            import.migrate_target()?;

            // Import all accounts in the backup
            let mut imported_accounts = Vec::new();
            let source_accounts = import.list_source_accounts()?;
            for account in &source_accounts {
                import.import_account(account).await?;
                imported_accounts.push(account.identity.clone());
            }

            imported_accounts
        }
    };

    Ok(accounts)
}
