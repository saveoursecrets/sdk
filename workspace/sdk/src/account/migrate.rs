//! Adds migration functions to an account.
use crate::{
    account::Account,
    migrate::{import::ImportTarget, AccountExport, AccountImport},
    vault::Summary,
    Result, Error,
};
use std::path::Path;

impl<D> Account<D> {
    /// Write a zip archive containing all the secrets
    /// for the account unencrypted.
    ///
    /// Used to migrate an account to another app.
    pub async fn export_unsafe_archive<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<()> {
        self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;
        let migration = AccountExport::new(self);
        Ok(migration.export_unsafe_archive(path).await?)
    }

    /// Import secrets from another app.
    pub async fn import_file(
        &mut self,
        target: ImportTarget,
    ) -> Result<Summary> {
        self.authenticated.as_ref().ok_or(Error::NotAuthenticated)?;
        let mut migration = AccountImport::new(self);
        Ok(migration.import_file(target).await?)
    }
}
