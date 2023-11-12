//! File system paths for a user account.
use crate::Result;
use std::path::{Path, PathBuf};

use crate::{
    constants::{
        AUDIT_FILE_NAME, DEVICES_DIR, FILES_DIR, LOCAL_DIR, TRASH_DIR,
        VAULTS_DIR, VAULT_EXT,
    },
    vfs,
};

use super::AppPaths;

/// Encapsulates the paths for a user account.
#[derive(Default, Debug, Clone)]
pub struct UserPaths {
    /// User identifier.
    user_id: String,
    /// Top-level documents folder.
    documents_dir: PathBuf,
    /// Directory for local storage.
    local_dir: PathBuf,
    /// File for local audit logs.
    audit_file: PathBuf,
    /// Trash for deleted data.
    trash_dir: PathBuf,
    /// User segregated storage.
    user_dir: PathBuf,
    /// User file storage.
    files_dir: PathBuf,
    /// User vault storage.
    vaults_dir: PathBuf,
    /// User devices storage.
    devices_dir: PathBuf,
}

impl UserPaths {
    /// Create new storage dirs.
    pub fn new<D: AsRef<Path>>(documents_dir: D, user_id: &str) -> Self {
        let documents_dir = documents_dir.as_ref().to_path_buf();
        let local_dir = documents_dir.join(LOCAL_DIR);
        let audit_file = local_dir.join(AUDIT_FILE_NAME);
        let trash_dir = local_dir.join(TRASH_DIR);
        let user_dir = local_dir.join(user_id);
        let files_dir = user_dir.join(FILES_DIR);
        let vaults_dir = user_dir.join(VAULTS_DIR);
        let devices_dir = user_dir.join(DEVICES_DIR);

        Self {
            user_id: user_id.to_owned(),
            documents_dir,
            local_dir,
            audit_file,
            trash_dir,
            user_dir,
            files_dir,
            vaults_dir,
            devices_dir,
        }
    }

    /// Ensure all the user directories exist.
    pub async fn ensure(&self) -> Result<()> {
        vfs::create_dir_all(&self.documents_dir).await?;
        vfs::create_dir_all(&self.local_dir).await?;
        vfs::create_dir_all(&self.trash_dir).await?;
        vfs::create_dir_all(&self.user_dir).await?;
        vfs::create_dir_all(&self.files_dir).await?;
        vfs::create_dir_all(&self.vaults_dir).await?;
        vfs::create_dir_all(&self.devices_dir).await?;
        Ok(())
    }

    /// Get the documents storage directory.
    pub fn documents_dir(&self) -> &PathBuf {
        &self.documents_dir
    }

    /// Audit file location.
    pub fn audit_file(&self) -> &PathBuf {
        &self.audit_file
    }

    /// Get the user storage directory.
    pub fn user_dir(&self) -> &PathBuf {
        &self.user_dir
    }

    /// Get the user files directory.
    pub fn files_dir(&self) -> &PathBuf {
        &self.files_dir
    }

    /// Get the user vaults storage directory.
    pub fn vaults_dir(&self) -> &PathBuf {
        &self.vaults_dir
    }

    /// Get the user devices directory.
    pub fn devices_dir(&self) -> &PathBuf {
        &self.devices_dir
    }

    /// Get the path to the identity vault file for this account.
    pub fn identity(&self) -> Result<PathBuf> {
        let identity_dir = AppPaths::identity_dir()?;
        let mut identity_vault_file = identity_dir.join(&self.user_id);
        identity_vault_file.set_extension(VAULT_EXT);
        Ok(identity_vault_file)
    }
}
