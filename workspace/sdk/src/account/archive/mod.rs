//! Read and write account backup archives.
mod backup;
mod zip;

pub use backup::{
    AccountBackup, AccountManifest, ExtractFilesLocation, ManifestEntry,
    RestoreOptions, RestoreTargets,
};
pub use zip::*;

use crate::{
    account::Account,
    events::EventKind,
    identity::{Identity, PublicIdentity},
    vfs::File,
    Paths, Result,
};
use secrecy::SecretString;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncSeek};

#[cfg(feature = "audit")]
use crate::audit::AuditEvent;

impl Account {
    /// Create a backup archive containing the
    /// encrypted data for the account.
    pub async fn export_backup_archive<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<()> {
        AccountBackup::export_archive_file(path, self.address(), &self.paths)
            .await?;

        #[cfg(feature = "audit")]
        {
            let audit_event = AuditEvent::new(
                EventKind::ExportBackupArchive,
                self.address().clone(),
                None,
            );
            self.paths.append_audit_events(vec![audit_event]).await?;
        }

        Ok(())
    }

    /// Read the inventory from an archive.
    pub async fn restore_archive_inventory<
        R: AsyncRead + AsyncSeek + Unpin,
    >(
        buffer: R,
    ) -> Result<Inventory> {
        let mut inventory =
            AccountBackup::restore_archive_inventory(buffer).await?;
        let accounts = Identity::list_accounts(None).await?;
        let exists_local = accounts
            .iter()
            .any(|account| account.address() == &inventory.manifest.address);
        inventory.exists_local = exists_local;
        Ok(inventory)
    }

    /// Restore from a backup archive file.
    pub async fn import_backup_archive<P: AsRef<Path>>(
        path: P,
        options: RestoreOptions,
        data_dir: Option<PathBuf>,
    ) -> Result<PublicIdentity> {
        let file = File::open(path).await?;
        let account =
            Self::import_archive_reader(file, options, data_dir.clone())
                .await?;

        #[cfg(feature = "audit")]
        {
            let audit_event = AuditEvent::new(
                EventKind::ImportBackupArchive,
                account.address().clone(),
                None,
            );

            let data_dir = if let Some(data_dir) = &data_dir {
                data_dir.clone()
            } else {
                Paths::data_dir()?
            };
            let paths = Paths::new(data_dir, account.address().to_string());
            paths.append_audit_events(vec![audit_event]).await?;
        }

        Ok(account)
    }

    /// Import from an archive reader.
    async fn import_archive_reader<R: AsyncRead + AsyncSeek + Unpin>(
        buffer: R,
        mut options: RestoreOptions,
        data_dir: Option<PathBuf>,
    ) -> Result<PublicIdentity> {
        let files_dir = ExtractFilesLocation::Builder(Box::new(|address| {
            let data_dir = Paths::data_dir().unwrap();
            let paths = Paths::new(data_dir, address);
            Some(paths.files_dir().to_owned())
        }));

        options.files_dir = Some(files_dir);

        let (_, account) =
            AccountBackup::import_archive_reader(buffer, options, data_dir)
                .await?;

        Ok(account)
    }

    /// Restore from a backup archive file.
    pub async fn restore_backup_archive<P: AsRef<Path>>(
        &mut self,
        path: P,
        password: SecretString,
        options: RestoreOptions,
        data_dir: Option<PathBuf>,
    ) -> Result<PublicIdentity> {
        let file = File::open(path).await?;
        let account = Self::restore_backup_reader(
            file, self, password, options, data_dir,
        )
        .await?;

        let audit_event = AuditEvent::new(
            EventKind::ImportBackupArchive,
            self.address().clone(),
            None,
        );
        self.paths.append_audit_events(vec![audit_event]).await?;

        Ok(account)
    }

    /// Restore from an archive reader.
    async fn restore_backup_reader<R: AsyncRead + AsyncSeek + Unpin>(
        reader: R,
        owner: &mut Account,
        password: SecretString,
        mut options: RestoreOptions,
        data_dir: Option<PathBuf>,
    ) -> Result<PublicIdentity> {

        let current_folder = {
            let storage = owner.storage()?;
            let reader = storage.read().await;
            reader.current_folder()
        };

        let files_dir =
            ExtractFilesLocation::Path(owner.paths().files_dir().clone());

        options.files_dir = Some(files_dir);

        let (targets, account) = AccountBackup::restore_archive_reader(
            reader, options, password, data_dir,
        )
        .await?;

        {
            let storage = owner.storage()?;
            let mut writer = storage.write().await;
            writer.restore_archive(&targets).await?;
        }

        owner.build_search_index().await?;

        if let Some(folder) = &current_folder {
            // Note that we don't want the additional
            // audit event here
            owner.open_vault(folder, false).await?;
        }

        Ok(account)
    }
}
