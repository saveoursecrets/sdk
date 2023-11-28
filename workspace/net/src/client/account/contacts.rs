//! Adds contacts functions to network account.
use crate::client::{NetworkAccount, Result};
use sos_sdk::{
    account::contacts::ContactImportProgress,
    vault::{secret::SecretId, Summary},
};
use std::path::Path;

impl NetworkAccount {
    /// Get an avatar JPEG image for a contact in the current
    /// open folder.
    pub async fn load_avatar(
        &mut self,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<Option<Vec<u8>>> {
        Ok(self.account.load_avatar(secret_id, folder).await?)
    }

    /// Export a contact secret to vCard file.
    pub async fn export_vcard_file<P: AsRef<Path>>(
        &mut self,
        path: P,
        secret_id: &SecretId,
        folder: Option<Summary>,
    ) -> Result<()> {
        Ok(self
            .account
            .export_vcard_file(path, secret_id, folder)
            .await?)
    }

    /// Export all contacts to a single vCard.
    pub async fn export_all_vcards<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<()> {
        Ok(self.account.export_all_vcards(path).await?)
    }

    /// Import vCards from a string buffer.
    pub async fn import_vcard(
        &mut self,
        content: &str,
        progress: impl Fn(ContactImportProgress),
    ) -> Result<()> {
        Ok(self.account.import_vcard(content, progress).await?)
    }
}
