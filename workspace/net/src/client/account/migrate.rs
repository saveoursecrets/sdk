//! Adds migration functions to network account.
use crate::client::{NetworkAccount, Result};
use sos_sdk::vault::Summary;
use std::path::Path;

#[cfg(feature = "migrate")]
use sos_migrate::{import::ImportTarget, AccountExport, AccountImport};

#[cfg(feature = "migrate")]
impl NetworkAccount {
    /// Write a zip archive containing all the secrets
    /// for the account unencrypted.
    ///
    /// Used to migrate an account to another app.
    pub async fn export_unsafe_archive<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<()> {
        let migration = AccountExport::new(&self.account);
        Ok(migration.export_unsafe_archive(path).await?)
    }

    /// Import secrets from another app.
    #[cfg(feature = "migrate")]
    pub async fn import_file(
        &mut self,
        target: ImportTarget,
    ) -> Result<Summary> {
        let _ = self.sync_lock.lock().await;
        let mut migration = AccountImport::new(&mut self.account);
        Ok(migration.import_file(target).await?)
    }
}
