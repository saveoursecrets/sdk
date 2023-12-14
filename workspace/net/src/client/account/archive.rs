//! Adds backup archive functions to network account.
use super::network_account::LocalAccount;
use crate::client::{NetworkAccount, Result};
use sos_sdk::{
    account::archive::{Inventory, RestoreOptions},
    identity::PublicIdentity,
};
use secrecy::SecretString;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncSeek};

impl NetworkAccount {
    /// Create a backup archive containing the
    /// encrypted data for the account.
    pub async fn export_backup_archive<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<()> {
        Ok(self.account.export_backup_archive(path).await?)
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
        Ok(LocalAccount::import_backup_archive(
            path,
            options,
            data_dir,
        )
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
        Ok(LocalAccount::restore_backup_archive(
            path,
            &mut owner.account,
            password,
            options,
            data_dir,
        )
        .await?)
    }
}
