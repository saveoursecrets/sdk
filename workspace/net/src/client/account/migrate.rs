//! Adds migration functions to network account.
use crate::client::{NetworkAccount, Result};
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
        Ok(self.account.export_unsafe_archive(path).await?)
    }

    /// Import secrets from another app.
    pub async fn import_file(
        &mut self,
        target: ImportTarget,
    ) -> Result<(Event, Summary)> {
        let _ = self.sync_lock.lock().await;
        Ok(self.account.import_file(target).await?)
    }
}
