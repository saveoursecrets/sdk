//! Export and import archives for any backend target.
use crate::{BackendTarget, Result};
use sos_core::{AccountId, Paths, PublicIdentity};
use sos_filesystem::archive::RestoreOptions;
use sos_vfs::File;
use std::path::Path;

/// Create a backup archive.
pub async fn export_backup_archive(
    output: impl AsRef<Path>,
    target: &BackendTarget,
    account_id: &AccountId,
) -> Result<()> {
    match target {
        BackendTarget::FileSystem(paths) => {
            use sos_filesystem::archive::AccountBackup;
            AccountBackup::export_archive_file(
                output.as_ref(),
                &account_id,
                paths,
            )
            .await?;
        }
        BackendTarget::Database(paths, _) => {
            use sos_database::archive;
            let db_path = paths.database_file();
            archive::create_backup_archive(db_path, paths, output.as_ref())
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
            use sos_filesystem::archive::{
                AccountBackup, ExtractFilesLocation,
            };
            use tokio::io::BufReader;

            let mut options: RestoreOptions = Default::default();
            if options.files_dir.is_none() {
                let files_dir =
                    ExtractFilesLocation::Builder(Box::new(|account_id| {
                        let data_dir = Paths::data_dir().unwrap();
                        let paths = Paths::new_client(data_dir)
                            .with_account_id(account_id);
                        Some(paths.files_dir().to_owned())
                    }));
                options.files_dir = Some(files_dir);
            }

            let file = File::open(input.as_ref()).await?;
            let (_, account) = AccountBackup::import_archive_reader(
                BufReader::new(file),
                options,
                Some(paths.documents_dir().to_owned()),
            )
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
