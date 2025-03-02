//! Upgrade backup archives.
use crate::{upgrade_accounts, Error, Result, UpgradeOptions};
use sos_backend::{
    archive::{
        export_backup_archive, import_backup_archive,
        try_read_backup_archive_manifest, ArchiveManifest,
    },
    BackendTarget,
};
use sos_core::Paths;
use sos_database::open_file;
use sos_vfs as vfs;
use std::path::Path;
use tempfile::tempdir;

/// Upgrade from a v1 or v2 backup archive to a
/// v3 database backup archive.
pub async fn upgrade_backup_archive(
    input: impl AsRef<Path>,
    output: impl AsRef<Path>,
) -> Result<()> {
    if vfs::try_exists(output.as_ref()).await? {
        return Err(Error::ArchiveFileAlreadyExists(
            output.as_ref().to_owned(),
        ));
    }

    let manifest = try_read_backup_archive_manifest(input.as_ref()).await?;
    match manifest {
        ArchiveManifest::V1(manifest) | ArchiveManifest::V2(manifest) => {
            let source_temp = tempdir()?;
            Paths::scaffold(Some(&source_temp.path().to_owned())).await?;
            let source_paths = Paths::new_client(source_temp.path())
                .with_account_id(&manifest.account_id);
            source_paths.ensure().await?;
            let target = BackendTarget::FileSystem(source_paths.clone());

            import_backup_archive(input.as_ref(), &target).await?;

            let options = UpgradeOptions {
                paths: source_paths.clone(),
                dry_run: false,
                ..Default::default()
            };
            upgrade_accounts(source_temp.path(), options).await?;

            let client = open_file(source_paths.database_file()).await?;
            let target = BackendTarget::Database(source_paths, client);
            export_backup_archive(
                output.as_ref(),
                &target,
                &manifest.account_id,
            )
            .await?;
            Ok(())
        }
        ArchiveManifest::V3(_) => {
            Err(Error::ArchiveAlreadyVersion3(input.as_ref().to_owned()))
        }
    }
}
