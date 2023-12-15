//! Adds migration functions to network account.
use crate::client::{sync::RemoteSync, NetworkAccount, Result, SyncError};
use sos_sdk::{events::Event, vault::Summary};
use std::path::Path;

use sos_sdk::migrate::import::ImportTarget;

impl NetworkAccount {
    /// Write a zip archive containing all the secrets
    /// for the account unencrypted.
    ///
    /// Used to migrate an account to another app.
    pub async fn export_unsafe_archive<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<()> {
        let account = self.account.lock().await;
        Ok(account.export_unsafe_archive(path).await?)
    }

    /// Import secrets from another app.
    pub async fn import_file(
        &mut self,
        target: ImportTarget,
    ) -> Result<((Event, Summary), Option<SyncError>)> {
        let _ = self.sync_lock.lock().await;

        let result = {
            let mut account = self.account.lock().await;
            account.import_file(target).await?
        };

        Ok((result, self.sync().await))
    }
}
