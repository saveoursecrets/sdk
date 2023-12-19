//! Adds backup archive functions to network account.
use crate::client::{NetworkAccount, Result};
use secrecy::SecretString;
use sos_sdk::{
    account::{archive::{Inventory, RestoreOptions}, LocalAccount},
    identity::PublicIdentity,
};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncSeek};

impl NetworkAccount {
    /// Create a backup archive containing the
    /// encrypted data for the account.
    pub async fn export_backup_archive<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<()> {
        let account = self.account.lock().await;
        Ok(account.export_backup_archive(path).await?)
    }

    /// Read the inventory from an archive.
    pub async fn restore_archive_inventory<
        R: AsyncRead + AsyncSeek + Unpin,
    >(
        buffer: R,
    ) -> Result<Inventory> {
        Ok(LocalAccount::restore_archive_inventory(buffer).await?)
    }

    /// Import from an archive file.
    pub async fn import_backup_archive<P: AsRef<Path>>(
        path: P,
        options: RestoreOptions,
        data_dir: Option<PathBuf>,
    ) -> Result<PublicIdentity> {
        Ok(LocalAccount::import_backup_archive(path, options, data_dir)
            .await?)
    }

    /// Restore from an archive file.
    pub async fn restore_backup_archive<P: AsRef<Path>>(
        path: P,
        owner: &mut NetworkAccount,
        password: SecretString,
        options: RestoreOptions,
        data_dir: Option<PathBuf>,
    ) -> Result<PublicIdentity> {
        let mut account = owner.account.lock().await;

        Ok(LocalAccount::restore_backup_archive(
            path,
            &mut *account,
            password,
            options,
            data_dir,
        )
        .await?)
    }
}
